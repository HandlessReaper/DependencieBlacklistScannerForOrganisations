#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GitHub Organization Dependency Denylist Scanner

Scannt alle Repositories einer GitHub-Organisation nach Abhängigkeiten, die auf
einer Blacklist (Denylist) stehen. Baut Dependency-Graphen auf, um zwischen
direkten und transitiven Dependencies zu unterscheiden.

Unterstützte Ecosystems:
- JavaScript/npm/yarn: package.json, package-lock.json v1/v2/v3, yarn.lock
- Python: requirements.txt, Pipfile/Pipfile.lock, poetry.lock, pyproject.toml
- PHP (Composer): composer.json, composer.lock
- Ruby (Bundler): Gemfile, Gemfile.lock
- Go: go.mod, go.sum (eingeschränkte Provenienz-Unterstützung)
- Java (Maven/Gradle): pom.xml, build.gradle, build.gradle.kts (nur direkte Dependencies)

Anforderungen:
- GITHUB_TOKEN oder GH_TOKEN mit Repo-Read-Rechten
- Optional: openpyxl (für Excel-Export), tomllib (für Python <3.11 TOML-Support)

Ausgabe: Terminal-Summary mit Provenienz-Ketten + Excel/CSV Export
"""

import argparse
import base64
import csv
import dataclasses
import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from typing import Dict, Iterable, List, Optional, Set, Tuple

import requests

try:
    from openpyxl import Workbook
except ImportError:
    Workbook = None  # type: ignore

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    tomllib = None  # type: ignore


# Konstanten
GITHUB_API = "https://api.github.com"
RAW_BASE = "https://raw.githubusercontent.com"

GITHUB_API_PAGE_SIZE = 100
GITHUB_API_DEFAULT_WAIT_SECONDS = 60

NPM_MAX_PROVENANCE_PATHS = 3
NPM_MAX_PROVENANCE_HOPS = 12
NPM_MAX_PATH_SAMPLES = 3
NPM_MAX_CHAINS_PER_PATH = 2

EXCEL_MAX_COLUMN_WIDTH = 80
EXCEL_COLUMN_PADDING = 2

DEFAULT_OUTPUT_FILE = "audit_results.xlsx"


SESSION = requests.Session()
SESSION.headers.update({
    "Accept": "application/vnd.github+json",
    "User-Agent": "org-dep-denylist-auditor/4.0",
})


# File-Sets pro Ecosystem
JS_FILES = {"package.json", "package-lock.json", "yarn.lock"}
PY_FILES = {"requirements.txt", "requirements-dev.txt", "requirements-prod.txt",
            "Pipfile", "Pipfile.lock", "poetry.lock", "pyproject.toml"}
PHP_FILES = {"composer.json", "composer.lock"}
JAVA_FILES = {"pom.xml", "build.gradle", "build.gradle.kts"}
GO_FILES = {"go.mod", "go.sum"}
RUBY_FILES = {"Gemfile", "Gemfile.lock"}

ECOSYSTEM_FILESETS = {
    "js": JS_FILES,
    "python": PY_FILES,
    "php": PHP_FILES,
    "java": JAVA_FILES,
    "go": GO_FILES,
    "ruby": RUBY_FILES,
}


@dataclasses.dataclass(frozen=True)
class Match:
    """Repräsentiert einen Treffer: Package auf Denylist in einem Repository."""
    org: str
    repo: str
    branch: str
    path: str
    ecosystem: str
    package: str
    version: str
    file_type: str
    scope: str          # "direct" | "transitive"
    via: str = ""       # Provenienz-Kette


# GitHub API Helpers

def require_token() -> None:
    """Prüft ob GitHub-Token vorhanden ist und setzt Authorization-Header."""
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if not token:
        print("ERROR: Please export GITHUB_TOKEN (or GH_TOKEN) with repo read access.", file=sys.stderr)
        sys.exit(2)
    SESSION.headers["Authorization"] = f"Bearer {token}"


def paginate(url: str, params: Optional[dict] = None) -> Iterable[dict]:
    """
    Paginiert durch GitHub API Responses.
    Handhabt Rate-Limiting automatisch via X-RateLimit-Reset Header.
    """
    # Create mutable copy to avoid modifying caller's dict
    params = dict(params or {})
    params.setdefault("per_page", GITHUB_API_PAGE_SIZE)

    while url:
        r = SESSION.get(url, params=params)

        # GitHub API rate limiting: wait until reset time or default 60s
        if r.status_code == 403 and "rate limit" in r.text.lower():
            reset = r.headers.get("X-RateLimit-Reset")
            wait = max(0, int(reset) - int(time.time())) if reset else GITHUB_API_DEFAULT_WAIT_SECONDS
            print(f"Rate limited. Sleeping {wait}s...", file=sys.stderr)
            time.sleep(wait)
            continue

        r.raise_for_status()
        data = r.json()

        if isinstance(data, list):
            yield from data
        else:
            yield data

        # Parse Link header for next page
        link = r.headers.get("Link", "")
        next_url = None
        if link:
            for part in link.split(","):
                m = re.search(r'<([^>]+)>; rel="next"', part)
                if m:
                    next_url = m.group(1)
                    break

        url = next_url
        params = None


def get_org_repos(org: str) -> List[dict]:
    """Holt alle Repositories einer Organisation."""
    return list(paginate(
        f"{GITHUB_API}/orgs/{org}/repos",
        params={"type": "all", "sort": "full_name"}
    ))


def get_repo_default_branch(repo: dict) -> str:
    """Extrahiert Default-Branch aus Repository-Metadaten."""
    return repo.get("default_branch", "main")


def _get_tree_sha(org: str, repo: str, branch: str) -> str:
    """
    Ermittelt Tree-SHA für Branch.
    Versucht zuerst direkt über Branch-Name, dann über Refs-API.
    """
    url = f"{GITHUB_API}/repos/{org}/{repo}/git/trees/{branch}"
    r = SESSION.get(url, params={"recursive": 1})

    if r.status_code == 200:
        return branch

    # Fallback: Resolve via refs API
    ref_url = f"{GITHUB_API}/repos/{org}/{repo}/git/refs/heads/{branch}"
    rr = SESSION.get(ref_url)
    rr.raise_for_status()
    return rr.json()["object"]["sha"]


def get_tree_paths(org: str, repo: str, branch: str) -> List[str]:
    """
    Fetch all file paths in repository tree recursively.
    Returns list of blob paths (files only, no directories).
    """
    sha = _get_tree_sha(org, repo, branch)
    url = f"{GITHUB_API}/repos/{org}/{repo}/git/trees/{sha}"
    r = SESSION.get(url, params={"recursive": 1})
    r.raise_for_status()
    data = r.json()
    return [item["path"] for item in data.get("tree", []) if item.get("type") == "blob"]


def fetch_raw_file(org: str, repo: str, branch: str, path: Optional[str]) -> Optional[str]:
    """
    Lädt Dateiinhalt von GitHub.
    Versucht zuerst Contents API (base64), dann raw.githubusercontent.com.
    Manche große oder binäre Dateien scheitern an Contents API.
    """
    if not path:
        return None

    # Try Contents API first (returns base64)
    api_url = f"{GITHUB_API}/repos/{org}/{repo}/contents/{path}"
    r = SESSION.get(api_url, params={"ref": branch})

    if r.status_code == 200 and r.headers.get("Content-Type", "").startswith("application/json"):
        try:
            data = r.json()
            if isinstance(data, dict) and data.get("encoding") == "base64" and "content" in data:
                return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        except Exception:
            pass

    # Fallback to raw.githubusercontent.com
    raw_url = f"{RAW_BASE}/{org}/{repo}/{branch}/{path}"
    rr = SESSION.get(raw_url)
    if rr.status_code == 200:
        return rr.text

    return None


# Export Helpers

def write_results(results: List[Match], out_path: str) -> None:
    """Schreibt Ergebnisse in CSV oder Excel, je nach Dateiendung."""
    ext = os.path.splitext(out_path)[1].lower()

    if ext == ".xlsx":
        _write_excel(results, out_path)
    else:
        _write_csv(results, out_path)


def _write_csv(results: List[Match], out_path: str) -> None:
    """Schreibt CSV mit Semikolon-Trenner und UTF-8 BOM (für deutsches Excel)."""
    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f, delimiter=';', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["org", "repo", "branch", "ecosystem", "file_type", "path",
                        "package", "version", "scope", "via"])
        for m in results:
            writer.writerow([m.org, m.repo, m.branch, m.ecosystem, m.file_type,
                           m.path, m.package, m.version, m.scope, m.via])


def _write_excel(results: List[Match], out_path: str) -> None:
    """Schreibt Excel-Datei mit automatischer Spaltenbreite."""
    if Workbook is None:
        raise RuntimeError("openpyxl nicht installiert. Bitte 'pip install openpyxl' oder CSV nutzen.")

    wb = Workbook()
    ws = wb.active
    ws.title = "Audit"

    headers = ["org", "repo", "branch", "ecosystem", "file_type", "path",
               "package", "version", "scope", "via"]
    ws.append(headers)

    for m in results:
        ws.append([m.org, m.repo, m.branch, m.ecosystem, m.file_type, m.path,
                  m.package, m.version, m.scope, m.via])

    # Auto-width mit Max-Limit
    for col in ws.columns:
        max_len = 0
        col_letter = col[0].column_letter
        for cell in col:
            try:
                max_len = max(max_len, len(str(cell.value)))
            except Exception:
                pass
        ws.column_dimensions[col_letter].width = min(max_len + EXCEL_COLUMN_PADDING, EXCEL_MAX_COLUMN_WIDTH)

    wb.save(out_path)


# Denylist Loader

def load_denylist(path: str) -> List[Tuple[str, str]]:
    """
    Lädt Denylist aus Datei.
    Format: name@version (JavaScript/Python/etc) oder group:artifact@version (Java/Maven).
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [entry for line in f if (entry := _parse_denylist_line(line))]
    except FileNotFoundError:
        print(f"ERROR: Denylist file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except IOError as e:
        print(f"ERROR: Cannot read denylist: {e}", file=sys.stderr)
        sys.exit(1)


def _parse_denylist_line(line: str) -> Optional[Tuple[str, str]]:
    """Parst einzelne Denylist-Zeile. Gibt (name, version) oder None zurück."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Standard-Format: name@version
    if "@" in line:
        name, ver = line.rsplit("@", 1)
        return (name.strip(), ver.strip())

    # Maven-Format: group:artifact:version (mindestens 3 Teile)
    if ":" in line:
        parts = line.split(":")
        if len(parts) >= 3:
            name = ":".join(parts[:-1])
            return (name.strip(), parts[-1].strip())

    print(f"WARN: Invalid denylist entry (expected name@version or group:artifact@version): {line}", file=sys.stderr)
    return None


# JavaScript / npm / yarn

def _npm_name_from_path(p: str) -> Optional[str]:
    """
    Extrahiert Package-Name aus npm-Pfad.
    Handhabt scoped packages (@scope/name) korrekt.
    Beispiel: "node_modules/@babel/core" -> "@babel/core"
    """
    if not p:
        return None

    parts = p.split("/")
    for i in range(len(parts) - 1, -1, -1):
        if parts[i] == "node_modules":
            # Check for scoped package (@scope/name)
            if i + 2 < len(parts) and parts[i + 1].startswith("@"):
                return parts[i + 1] + "/" + parts[i + 2]
            if i + 1 < len(parts):
                return parts[i + 1]
            break

    return None


def js_declared_from_package_json(content: str) -> Set[str]:
    """Extrahiert alle deklarierten Dependencies aus package.json (lowercase)."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return set()

    names = set()
    sections = ["dependencies", "devDependencies", "peerDependencies",
                "optionalDependencies", "bundledDependencies"]

    for section in sections:
        deps = data.get(section, {}) or {}
        if isinstance(deps, dict):
            names.update(n.lower() for n in deps.keys())

    return names


def _npm_build_graph_from_lock_v2(data: dict) -> Tuple[
    Set[str],                          # direct_top_names (lowercase)
    Dict[str, Set[str]],               # parents_by_path
    Dict[str, Tuple[str, str]],        # nv_by_path: path -> (name, version)
    Dict[Tuple[str, str], Set[str]]    # paths_by_nv: (name, version) -> {paths}
]:
    """
    Build dependency graph from package-lock.json v2/v3 format.

    npm v7+ nutzt "hoisting": ein Package kann an mehreren Pfaden installiert sein.
    Daher wird der Graph pfad-basiert aufgebaut, nicht nur name-basiert.

    Returns: direct deps, parent relationships, package metadata, paths per package
    """
    packages = data.get("packages", {})
    nv_by_path: Dict[str, Tuple[str, str]] = {}
    deps_by_path: Dict[str, Dict[str, str]] = {}

    # Parse all packages and their dependencies
    for path, meta in packages.items():
        if not isinstance(meta, dict):
            continue

        name = meta.get("name") or _npm_name_from_path(path)
        version = meta.get("version")

        if path == "":  # root package
            name = name or "<root>"
            version = version or ""

        if not (name and version):
            continue

        nv_by_path[path] = (name, str(version))

        deps = meta.get("dependencies", {}) or {}
        deps_by_path[path] = {k: str(deps[k]) for k in deps.keys()} if isinstance(deps, dict) else {}

    # Extract direct dependencies from root
    direct_top_names: Set[str] = set()
    root_meta = packages.get("", {})
    if isinstance(root_meta, dict):
        root_deps = root_meta.get("dependencies", {}) or {}
        if isinstance(root_deps, dict):
            direct_top_names = {k.lower() for k in root_deps.keys()}

    # npm hoisting means a dependency may be installed at parent level instead of nested
    # Check from most specific to most general path
    def _candidate_child_paths(parent_path: str, dep_name: str) -> List[str]:
        """Generiert mögliche Pfade für Child-Dependency unter Berücksichtigung von Hoisting."""
        base = f"{parent_path}/node_modules/{dep_name}" if parent_path else f"node_modules/{dep_name}"
        paths = [base, f"node_modules/{dep_name}"]

        if parent_path:
            parts = parent_path.split("/")
            for i in range(len(parts) - 1, -1, -1):
                pp = "/".join(parts[:i])
                cand = f"{pp + '/' if pp else ''}node_modules/{dep_name}"
                if cand not in paths:
                    paths.append(cand)

        return paths

    # Build parent relationships
    parents_by_path: Dict[str, Set[str]] = defaultdict(set)
    for parent_path, deps in deps_by_path.items():
        for dep_name in deps.keys():
            for candidate_path in _candidate_child_paths(parent_path, dep_name):
                if candidate_path in nv_by_path:
                    parents_by_path[candidate_path].add(parent_path)
                    break

    # Build reverse index: (name, version) -> {paths}
    paths_by_nv: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    for path, nv in nv_by_path.items():
        paths_by_nv[nv].add(path)

    return direct_top_names, parents_by_path, nv_by_path, paths_by_nv


def _npm_provenance_chains(
    child_path: str,
    direct_top_names: Set[str],
    parents_by_path: Dict[str, Set[str]],
    nv_by_path: Dict[str, Tuple[str, str]],
    max_paths: int = NPM_MAX_CHAINS_PER_PATH,
    max_hops: int = NPM_MAX_PROVENANCE_HOPS
) -> List[List[Tuple[str, str, str]]]:
    """
    Trace dependency path from transitive package back to direct dependency.

    Nutzt BFS um Pfade von transitiver Dependency zurück zu direkter Dependency zu finden.
    Limits verhindern Endlosschleifen bei zirkulären Dependencies.

    Returns chains like: [(direct_dep, ver, path) -> (intermediate, ver, path) -> (target, ver, path)]
    """
    chains: List[List[Tuple[str, str, str]]] = []

    if child_path not in nv_by_path:
        return chains

    n, v = nv_by_path[child_path]
    q = deque()
    q.append(([(n, v, child_path)], child_path))
    seen = {child_path}

    while q and len(chains) < max_paths:
        path_nv, cur = q.popleft()

        if len(path_nv) > max_hops:
            continue

        for par in parents_by_path.get(cur, set()):
            if par not in nv_by_path:
                continue

            pn, pv = nv_by_path[par]
            new_chain = [(pn, pv, par)] + path_nv

            if pn.lower() in direct_top_names:
                chains.append(new_chain)
                if len(chains) >= max_paths:
                    break

            if par not in seen:
                seen.add(par)
                q.append((new_chain, par))

    return chains


def js_matches_package_json(content: str, deny: List[Tuple[str, str]]) -> List[Tuple[str, str, str]]:
    """
    Matched Denylist gegen package.json.
    Handhabt nur exakte Versionen, ^version und ~version (häufigste Fälle).
    Andere Specifier (>=, <=, *, etc.) werden nicht gemacht, da package.json allein
    nicht die installierte Version garantiert.
    """
    out: List[Tuple[str, str, str]] = []

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return out

    sections = ["dependencies", "devDependencies", "peerDependencies",
                "optionalDependencies", "bundledDependencies"]

    for dn, dv in deny:
        for section in sections:
            deps = data.get(section, {}) or {}
            if not isinstance(deps, dict):
                continue

            for name, spec in deps.items():
                # Simple version matching: exact, caret (^), tilde (~)
                if name.strip().lower() == dn.strip().lower():
                    spec_str = str(spec).strip()
                    if spec_str in (dv, f"^{dv}", f"~{dv}"):
                        out.append((dn, dv, "direct"))
                        break

    return out


def _js_matches_lock_v2(
    data: dict,
    deny: List[Tuple[str, str]],
    declared_direct: Set[str]
) -> List[Tuple[str, str, str, str]]:
    """Matched package-lock.json v2/v3 gegen Denylist mit Provenienz-Chains."""
    out: List[Tuple[str, str, str, str]] = []

    direct_top, parents_by_path, nv_by_path, paths_by_nv = _npm_build_graph_from_lock_v2(data)
    deny_lookup = {(dn.lower(), dv): dn for dn, dv in deny}

    for (n, v), all_paths in sorted(paths_by_nv.items(), key=lambda x: (x[0][0].lower(), x[0][1])):
        key = (n.lower(), v)
        if key not in deny_lookup:
            continue

        orig = deny_lookup[key]
        scope = "direct" if n.lower() in declared_direct else "transitive"

        if scope == "direct":
            sample = next(iter(all_paths)) if all_paths else ""
            via = f"{n}@{v} [{sample}]" if sample else ""
            out.append((orig, v, scope, via))
            continue

        # Transitive: Build provenance chains
        seen_vias: Set[str] = set()
        for child_path in list(all_paths)[:NPM_MAX_PATH_SAMPLES]:
            chains = _npm_provenance_chains(child_path, direct_top, parents_by_path, nv_by_path)

            if not chains:
                via_txt = f"{n}@{v} [{child_path}]"
                if via_txt not in seen_vias:
                    out.append((orig, v, scope, via_txt))
                    seen_vias.add(via_txt)
                continue

            for chain in chains:
                via_txt = " -> ".join([f"{cn}@{cv} [{cp}]" for (cn, cv, cp) in chain])
                if via_txt not in seen_vias:
                    out.append((orig, v, scope, via_txt))
                    seen_vias.add(via_txt)

    return out


def _js_matches_lock_v1(
    data: dict,
    deny: List[Tuple[str, str]],
    declared_direct: Set[str]
) -> List[Tuple[str, str, str, str]]:
    """
    Matched package-lock.json v1 gegen Denylist.
    v1 nutzt nested "dependencies" tree statt flat "packages" dict.
    """
    out: List[Tuple[str, str, str, str]] = []
    deny_lookup = {(dn.lower(), dv): dn for dn, dv in deny}

    def walk(obj, stack: List[Tuple[str, str]]) -> None:
        if not isinstance(obj, dict):
            return

        for name, meta in obj.items():
            if not isinstance(meta, dict):
                continue

            version = str(meta.get("version", ""))
            key = (name.lower(), version)

            if key in deny_lookup:
                orig = deny_lookup[key]
                scope = "direct" if name.lower() in declared_direct else "transitive"
                via = " -> ".join([f"{pn}@{pv}" for (pn, pv) in stack + [(name, version)]]) if scope == "transitive" and stack else ""
                out.append((orig, version, scope, via))

            deps = meta.get("dependencies")
            if isinstance(deps, dict):
                walk(deps, stack + [(name, version)])

    walk(data.get("dependencies", {}), [])
    return out


def js_matches_package_lock(
    content: str,
    deny: List[Tuple[str, str]],
    declared_direct: Set[str]
) -> List[Tuple[str, str, str, str]]:
    """Matched package-lock.json (v1/v2/v3) gegen Denylist."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    # Try v2/v3 format first (has "packages" dict)
    if isinstance(data.get("packages"), dict):
        return _js_matches_lock_v2(data, deny, declared_direct)

    # Fallback to v1 format (nested "dependencies" tree)
    if "dependencies" in data:
        return _js_matches_lock_v1(data, deny, declared_direct)

    return []


def js_matches_yarn_lock(
    content: str,
    deny: List[Tuple[str, str]],
    declared_direct: Set[str]
) -> List[Tuple[str, str, str]]:
    """Matched yarn.lock gegen Denylist."""
    out: List[Tuple[str, str, str]] = []
    blocks = re.split(r"\n\s*\n", content)

    for block in blocks:
        mver = re.search(r'\n\s*version\s+"([^"]+)"', block)
        if not mver:
            continue

        ver = mver.group(1)
        headers = [h.strip().strip(":") for h in re.findall(r'^[^\n]+:\n', block, flags=re.M)]

        for header in headers:
            # Extract package name from header (handles scoped packages)
            name = header.split("@", 1)[0] if not header.startswith("@") else header[:header.rfind("@")]

            for dn, dv in deny:
                if dn == name and dv == ver:
                    scope = "direct" if name.lower() in declared_direct else "transitive"
                    out.append((dn, dv, scope))

    return out


# PHP / Composer

def php_declared_from_composer_json(content: str) -> Set[str]:
    """Extrahiert deklarierte Dependencies aus composer.json."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return set()

    names = set()
    for section in ("require", "require-dev"):
        deps = data.get(section, {}) or {}
        if isinstance(deps, dict):
            names.update(deps.keys())

    return names


def _normalize_php_ver(v: str) -> str:
    """Normalisiert PHP-Version (entfernt führendes 'v')."""
    return v.lstrip("v")


def _php_build_graph_from_lock(content: str) -> Tuple[
    Dict[Tuple[str, str], Set[Tuple[str, str]]],  # parents: child(name, "") -> {parent(name, version)}
    Dict[str, Set[str]]                            # versions: name -> {versions}
]:
    """
    Build dependency graph from composer.lock.

    Challenge: "require" listet nur Dependency-Namen ohne Versionen.
    Lösung: Versions separat speichern und bei Bedarf nachschlagen.
    """
    parents: Dict[Tuple[str, str], Set[Tuple[str, str]]] = defaultdict(set)
    versions: Dict[str, Set[str]] = defaultdict(set)

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return parents, versions

    def _process_section(section_name: str) -> None:
        """Verarbeitet 'packages' oder 'packages-dev' Section."""
        for pkg in data.get(section_name, []) or []:
            name = pkg.get("name")
            ver = _normalize_php_ver(str(pkg.get("version", "")))

            if not (name and ver):
                continue

            versions[name].add(ver)

            requires = pkg.get("require", {}) or {}
            for child_name, _spec in requires.items():
                # Store child with empty version (will be resolved later from versions dict)
                parents[(child_name, "")].add((name, ver))

    _process_section("packages")
    _process_section("packages-dev")

    return parents, versions


def composer_lock_matches(
    content: str,
    deny: List[Tuple[str, str]],
    declared_direct: Set[str]
) -> List[Tuple[str, str, str, str]]:
    """Matched composer.lock gegen Denylist mit Parent-Chains."""
    out: List[Tuple[str, str, str, str]] = []

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return out

    parents, versions = _php_build_graph_from_lock(content)

    # Pre-compute latest version per package (for parent strings)
    latest_version: Dict[str, str] = {}
    for pkg_name, vers in versions.items():
        if vers:
            latest_version[pkg_name] = sorted(vers)[-1]

    def _parent_strs(child_name: str, child_ver: str) -> List[str]:
        """Generiert Parent-Strings für Child-Package."""
        plist = []
        for (pn, pv) in parents.get((child_name, ""), set()):
            pv2 = pv or latest_version.get(pn, "")
            plist.append(f"{pn}@{pv2}" if pv2 else pn)
        return plist

    # Collect all present packages
    present = []
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []) or []:
            name = pkg.get("name")
            ver = _normalize_php_ver(str(pkg.get("version", "")))
            if name and ver:
                present.append((name, ver))

    deny_set = set((_n, _v) for _n, _v in deny)

    for (name, ver) in present:
        if (name, ver) not in deny_set:
            continue

        scope = "direct" if name in declared_direct else "transitive"
        via = ""

        if scope == "transitive":
            ps = _parent_strs(name, ver)
            if ps:
                via = " | ".join([f"{p} -> {name}@{ver}" for p in ps])

        out.append((name, ver, scope, via))

    return out


# Python (pip / pipenv / poetry)

def _normalize_python_name(n: str) -> str:
    """Normalisiert Python-Package-Namen (- und _ werden zu -, lowercase)."""
    return re.sub(r"[-_]+", "-", n).lower()


def _py_declared_from_pipfile(content: str) -> Set[str]:
    """Extrahiert deklarierte Dependencies aus Pipfile."""
    if not tomllib:
        return set()

    try:
        data = tomllib.loads(content)
    except Exception:
        return set()

    names = set()
    for section in ("packages", "dev-packages"):
        deps = data.get(section, {}) if isinstance(data, dict) else {}
        if isinstance(deps, dict):
            names.update(_normalize_python_name(n) for n in deps.keys())

    return names


def _py_declared_from_pyproject(content: str) -> Set[str]:
    """Extrahiert deklarierte Dependencies aus pyproject.toml."""
    if not tomllib:
        return set()

    try:
        data = tomllib.loads(content)
    except Exception:
        return set()

    names = set()
    sections = [
        ("project", "dependencies"),
        ("tool", "poetry", "dependencies"),
        ("tool", "poetry", "dev-dependencies")
    ]

    for section_path in sections:
        d = data
        for key in section_path:
            d = d.get(key, {}) if isinstance(d, dict) else {}

        if isinstance(d, (list, tuple)):
            for s in d:
                m = re.match(r"([A-Za-z0-9_.\-]+)", str(s))
                if m:
                    names.add(_normalize_python_name(m.group(1)))
        elif isinstance(d, dict):
            names.update(_normalize_python_name(n) for n in d.keys())

    return names


def py_declared_from_manifests(pipfile: Optional[str], pyproject: Optional[str]) -> Set[str]:
    """Kombiniert deklarierte Python-Dependencies aus Pipfile und pyproject.toml."""
    declared: Set[str] = set()

    if pipfile:
        declared |= _py_declared_from_pipfile(pipfile)
    if pyproject:
        declared |= _py_declared_from_pyproject(pyproject)

    return declared


def _python_build_graph_from_lock(content: str, format_type: str) -> Tuple[
    Dict[Tuple[str, str], Set[Tuple[str, str]]],  # parents
    Dict[str, Set[str]]                            # versions
]:
    """
    Build dependency graph from Python lock file.
    Unterstützt Pipfile.lock (JSON) und poetry.lock (TOML).
    """
    parents: Dict[Tuple[str, str], Set[Tuple[str, str]]] = defaultdict(set)
    versions: Dict[str, Set[str]] = defaultdict(set)

    if format_type == "pipfile":
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return parents, versions

        # First pass: collect versions
        for section in ("default", "develop"):
            pkgs = data.get(section, {}) or {}
            for pname, meta in pkgs.items():
                ver = str((meta or {}).get("version", "")).lstrip("=")
                if ver:
                    versions[_normalize_python_name(pname)].add(ver)

        # Second pass: build parent relationships
        for section in ("default", "develop"):
            pkgs = data.get(section, {}) or {}
            for pname, meta in pkgs.items():
                pnorm = _normalize_python_name(pname)
                pver = str((meta or {}).get("version", "")).lstrip("=")
                deps = (meta or {}).get("dependencies", {}) or {}

                for child_name, _spec in deps.items():
                    cnorm = _normalize_python_name(child_name)
                    parents[(cnorm, "")].add((pnorm, pver))

    elif format_type == "poetry":
        if not tomllib:
            return parents, versions

        try:
            data = tomllib.loads(content)
        except Exception:
            return parents, versions

        # First pass: collect versions
        for pkg in data.get("package", []) or []:
            name = _normalize_python_name(pkg.get("name", ""))
            ver = str(pkg.get("version", ""))
            if name and ver:
                versions[name].add(ver)

        # Second pass: build parent relationships
        for pkg in data.get("package", []) or []:
            pn = _normalize_python_name(pkg.get("name", ""))
            pv = str(pkg.get("version", ""))
            deps = pkg.get("dependencies", {}) or {}

            for child_name in deps.keys():
                cn = _normalize_python_name(child_name)
                parents[(cn, "")].add((pn, pv))

    return parents, versions


def python_requirements_matches(content: str, deny: List[Tuple[str, str]]) -> List[Tuple[str, str, str]]:
    """Matched requirements.txt gegen Denylist (nur exakte Versionen mit ==)."""
    out: List[Tuple[str, str, str]] = []
    deny_norm = {(_normalize_python_name(n), v): (n, v) for n, v in deny}

    for line in content.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue

        m = re.match(r"([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)", s)
        if not m:
            continue

        name_norm = _normalize_python_name(m.group(1))
        ver = m.group(2)

        if (name_norm, ver) in deny_norm:
            orig_name, orig_ver = deny_norm[(name_norm, ver)]
            out.append((orig_name, orig_ver, "direct"))

    return out


def python_lock_matches(
    content: str,
    deny: List[Tuple[str, str]],
    declared_direct: Set[str],
    flavor: str
) -> List[Tuple[str, str, str, str]]:
    """
    Matched Python lock files gegen Denylist mit Parent-Chains.
    flavor: "pipfile" (Pipfile.lock) oder "poetry" (poetry.lock)
    """
    out: List[Tuple[str, str, str, str]] = []

    parents, versions = _python_build_graph_from_lock(content, flavor)

    # Parse lock file to get present packages
    present: List[Tuple[str, str]] = []

    if flavor == "pipfile":
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return out

        for section in ("default", "develop"):
            pkgs = data.get(section, {}) or {}
            for name, meta in pkgs.items():
                ver = str((meta or {}).get("version", "")).lstrip("=")
                if ver:
                    present.append((_normalize_python_name(name), ver))

    elif flavor == "poetry":
        if not tomllib:
            return out

        try:
            data = tomllib.loads(content)
        except Exception:
            return out

        for pkg in data.get("package", []) or []:
            name = _normalize_python_name(pkg.get("name", ""))
            ver = str(pkg.get("version", ""))
            if name and ver:
                present.append((name, ver))

    deny_norm = {(_normalize_python_name(n), v): (n, v) for n, v in deny}

    for (name_norm, ver) in present:
        if (name_norm, ver) not in deny_norm:
            continue

        orig_name, orig_ver = deny_norm[(name_norm, ver)]
        scope = "direct" if name_norm in declared_direct else "transitive"
        via = ""

        if scope == "transitive":
            plist = sorted(parents.get((name_norm, ""), set()))
            if plist:
                via = " | ".join([f"{pn}@{pv} -> {orig_name}@{orig_ver}" for (pn, pv) in plist])

        out.append((orig_name, orig_ver, scope, via))

    return out


def python_pyproject_direct(content: str, deny: List[Tuple[str, str]]) -> List[Tuple[str, str, str]]:
    """Matched pyproject.toml gegen Denylist (nur direkte Dependencies)."""
    out: List[Tuple[str, str, str]] = []

    if not tomllib:
        return out

    try:
        data = tomllib.loads(content)
    except Exception:
        return out

    def _check_section(deps: dict) -> None:
        """Prüft Dependency-Section auf Denylist-Treffer."""
        for name, spec in (deps or {}).items():
            if isinstance(spec, str):
                for dn, dv in deny:
                    if _normalize_python_name(dn) == _normalize_python_name(name) and spec.strip() == dv:
                        out.append((dn, dv, "direct"))
            elif isinstance(spec, dict) and "version" in spec:
                for dn, dv in deny:
                    if _normalize_python_name(dn) == _normalize_python_name(name) and str(spec["version"]).strip() == dv:
                        out.append((dn, dv, "direct"))

    sections = [
        ("tool", "poetry", "dependencies"),
        ("tool", "poetry", "dev-dependencies")
    ]

    for section_path in sections:
        d = data
        for key in section_path:
            d = d.get(key, {}) if isinstance(d, dict) else {}

        if isinstance(d, dict):
            _check_section(d)

    return out


# Ruby / Bundler

def ruby_declared_from_gemfile(content: str) -> Set[str]:
    """Extrahiert deklarierte Gems aus Gemfile."""
    names = set()
    for line in content.splitlines():
        m = re.search(r'\bgem\s+["\']([^"\']+)["\']', line)
        if m:
            names.add(m.group(1))
    return names


def ruby_build_graph_gemfile_lock(content: str) -> Tuple[
    Dict[Tuple[str, str], Set[Tuple[str, str]]],  # parents
    Set[Tuple[str, str]]                           # present
]:
    """
    Parse Gemfile.lock dependency graph via indentation-based tree structure.
    Child gems sind unter parent gems eingerückt in der "specs:" section.
    """
    parents: Dict[Tuple[str, str], Set[Tuple[str, str]]] = defaultdict(set)
    present: Set[Tuple[str, str]] = set()

    in_specs = False
    stack: List[Tuple[int, str, str]] = []

    for line in content.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            stack.clear()
            continue

        if not in_specs:
            continue

        # Section ended (non-indented line)
        if line and not line.startswith(" "):
            in_specs = False
            break

        m = re.match(r'(\s*)([A-Za-z0-9_.\-]+)\s+\(([^)]+)\)', line)
        if not m:
            continue

        indent = len(m.group(1))
        name = m.group(2)
        ver = m.group(3)

        # Pop stack until we find parent at lower indent
        while stack and stack[-1][0] >= indent:
            stack.pop()

        # Add all stack items as parents
        for (_ind, pn, pv) in stack:
            parents[(name, ver)].add((pn, pv))

        stack.append((indent, name, ver))
        present.add((name, ver))

    return parents, present


# Go

def _parse_go_require_line(line: str) -> Optional[Tuple[str, str, bool]]:
    """
    Parse go.mod require line.
    Returns (module, version, is_indirect) oder None.
    """
    m = re.match(r"([^\s]+)\s+v?([0-9][^\s]*)(?:\s+//\s+indirect)?", line)
    if not m:
        return None

    mod = m.group(1)
    ver = m.group(2)
    indirect = "// indirect" in line

    return (mod, ver, indirect)


def go_direct_from_gomod(content: str) -> Set[Tuple[str, str, bool]]:
    """
    Parse go.mod require directives.
    Returns (module, version, is_indirect) tuples.
    "// indirect" comment indicates transitive dependency.
    """
    direct: Set[Tuple[str, str, bool]] = set()
    in_block = False

    for raw in content.splitlines():
        line = raw.strip()

        if not line or line.startswith("//"):
            continue

        if line.startswith("require ("):
            in_block = True
            continue

        if in_block and line == ")":
            in_block = False
            continue

        # Handle both in-block and single-line require
        if in_block:
            parsed = _parse_go_require_line(line)
            if parsed:
                direct.add(parsed)
        elif line.startswith("require "):
            require_line = line[len("require "):].strip()
            parsed = _parse_go_require_line(require_line)
            if parsed:
                direct.add(parsed)

    return direct


def go_sum_present(content: str) -> Set[Tuple[str, str]]:
    """Extrahiert alle Packages aus go.sum."""
    pres: Set[Tuple[str, str]] = set()

    for raw in content.splitlines():
        s = raw.strip()
        if not s:
            continue

        parts = s.split()
        if len(parts) < 2:
            continue

        mod = parts[0]
        ver = parts[1]

        # Strip /go.mod suffix if present
        if ver.endswith("/go.mod"):
            ver = ver[:-7]

        pres.add((mod, ver.lstrip("v")))

    return pres


# Java (Maven / Gradle)

def java_matches_pom_xml(content: str, deny: List[Tuple[str, str]]) -> Set[Tuple[str, str]]:
    """
    Parse Maven pom.xml.
    Keine transitive Resolution (würde Maven-Resolver benötigen).
    Matched nur direkte Dependencies in <dependencies> section.
    """
    found = set()

    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        print(f"WARN: Invalid pom.xml: {e}", file=sys.stderr)
        return set()

    # Determine namespace
    ns_match = re.match(r'\{([^}]+)\}', root.tag)
    ns = {"m": ns_match.group(1)} if ns_match else {}
    ns_prefix = "m:" if ns else ""

    for dep in root.findall(f".//{ns_prefix}dependency", ns):
        # Cache find results to avoid triple-find inefficiency
        gid_elem = dep.find(f"{ns_prefix}groupId", ns)
        aid_elem = dep.find(f"{ns_prefix}artifactId", ns)
        ver_elem = dep.find(f"{ns_prefix}version", ns)

        gid = gid_elem.text.strip() if gid_elem is not None and gid_elem.text else ""
        aid = aid_elem.text.strip() if aid_elem is not None and aid_elem.text else ""
        ver = ver_elem.text.strip() if ver_elem is not None and ver_elem.text else ""

        if not (gid and aid and ver):
            continue

        coord = f"{gid}:{aid}"

        for dn, dv in deny:
            if ":" in dn and dn == coord and dv == ver:
                found.add((dn, dv))

    return found


def java_matches_gradle(content: str, deny: List[Tuple[str, str]]) -> Set[Tuple[str, str]]:
    """Matched Gradle build files gegen Denylist (Regex-basiert, keine vollständige Parsing)."""
    found = set()

    pattern = r'\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s+(["\'])([^"\']+):(\S+?):([^"\']+)\1'

    for m in re.finditer(pattern, content):
        group = m.group(2)
        artifact = m.group(3)
        ver = m.group(4)
        coord = f"{group}:{artifact}"

        for dn, dv in deny:
            if ":" in dn and dn == coord and dv == ver:
                found.add((dn, dv))

    return found


# Main Audit Logic

def _get_repository_file_paths(org: str, repo_name: str, branch: str) -> List[str]:
    """Fetch all file paths in repository."""
    try:
        return get_tree_paths(org, repo_name, branch)
    except Exception as e:
        print(f"WARN: Cannot list tree for {org}/{repo_name}@{branch}: {e}", file=sys.stderr)
        return []


def _filter_dependency_files(paths: List[str], ecosystem: str) -> Set[str]:
    """Filter paths to only dependency manifest files for specified ecosystem."""
    if ecosystem == "all":
        wanted = set().union(*ECOSYSTEM_FILESETS.values())
    else:
        wanted = ECOSYSTEM_FILESETS.get(ecosystem, set())

    return {p for p in paths if os.path.basename(p) in wanted}


def _preload_manifest_files(
    org: str,
    repo: str,
    branch: str,
    targets: Set[str],
    all_paths: List[str]
) -> Dict[str, Optional[str]]:
    """
    Pre-load manifest files needed to determine direct dependencies.
    Diese Dateien werden benötigt, um später bei Lock-Files zwischen direct und
    transitive Dependencies zu unterscheiden.
    """
    manifests: Dict[str, Optional[str]] = {}
    file_names = {os.path.basename(t) for t in targets}
    all_names = {os.path.basename(p) for p in all_paths}

    def _fetch_first(filename: str, search_in: Set[str]) -> Optional[str]:
        """Finds and fetches first matching file."""
        for p in search_in:
            if os.path.basename(p) == filename:
                return fetch_raw_file(org, repo, branch, p)
        return None

    if "package.json" in file_names:
        manifests["package.json"] = _fetch_first("package.json", targets)

    if "composer.json" in file_names:
        manifests["composer.json"] = _fetch_first("composer.json", targets)

    # Pipfile might not be in targets but in all_paths
    if "Pipfile" in all_names:
        pipfile_path = next((p for p in all_paths if os.path.basename(p) == "Pipfile"), None)
        if pipfile_path:
            manifests["Pipfile"] = fetch_raw_file(org, repo, branch, pipfile_path)

    if "pyproject.toml" in file_names:
        manifests["pyproject.toml"] = _fetch_first("pyproject.toml", targets)

    if "Gemfile" in all_names:
        gemfile_path = next((p for p in all_paths if os.path.basename(p) == "Gemfile"), None)
        if gemfile_path:
            manifests["Gemfile"] = fetch_raw_file(org, repo, branch, gemfile_path)

    if "go.mod" in file_names:
        manifests["go.mod"] = _fetch_first("go.mod", targets)

    return manifests


def _extract_declared_dependencies(manifests: Dict[str, Optional[str]]) -> Dict[str, Set]:
    """
    Extract declared (direct) dependencies from manifest files.
    Wird verwendet um bei Lock-Files zwischen direct und transitive zu unterscheiden.
    """
    declared: Dict[str, Set] = {
        "js": set(),
        "php": set(),
        "python": set(),
        "ruby": set(),
        "go_names": set(),
        "go_triplets": set(),
    }

    if pkg_json := manifests.get("package.json"):
        declared["js"] = js_declared_from_package_json(pkg_json)

    if composer_json := manifests.get("composer.json"):
        declared["php"] = php_declared_from_composer_json(composer_json)

    pipfile = manifests.get("Pipfile")
    pyproject = manifests.get("pyproject.toml")
    declared["python"] = py_declared_from_manifests(pipfile, pyproject)

    if gemfile := manifests.get("Gemfile"):
        declared["ruby"] = ruby_declared_from_gemfile(gemfile)

    if gomod := manifests.get("go.mod"):
        go_triplets = go_direct_from_gomod(gomod)
        declared["go_triplets"] = go_triplets
        declared["go_names"] = {mod for (mod, _v, ind) in go_triplets if not ind}

    return declared


def audit_repo(
    org: str,
    repo_name: str,
    branch: str,
    ecosystem: str,
    deny_pairs: List[Tuple[str, str]]
) -> List[Match]:
    """
    Audit a single repository for denylist matches.

    Workflow:
    1. List all files in repo
    2. Filter to dependency manifests
    3. Pre-load manifest files (package.json, composer.json, etc.) for direct dep detection
    4. Process each dependency file and match against denylist
    """
    results: List[Match] = []

    # 1. Discover files
    paths = _get_repository_file_paths(org, repo_name, branch)
    if not paths:
        return results

    # 2. Filter to relevant dependency files
    targets = _filter_dependency_files(paths, ecosystem)
    if not targets:
        return results

    # 3. Pre-load manifests for direct dependency detection
    manifests = _preload_manifest_files(org, repo_name, branch, targets, paths)

    # 4. Extract declared dependencies
    declared = _extract_declared_dependencies(manifests)

    # 5. Process each dependency file
    for path in sorted(targets):
        content = fetch_raw_file(org, repo_name, branch, path)
        if content is None:
            continue

        base = os.path.basename(path)
        eco: Optional[str] = None

        # JavaScript / npm / yarn
        if base in JS_FILES and ecosystem in ("js", "all"):
            eco = "js"

            if base == "package.json":
                for (pkg, ver, scope) in js_matches_package_json(content, deny_pairs):
                    results.append(Match(org, repo_name, branch, path, eco, pkg, ver, base, scope))

            elif base == "package-lock.json":
                for (pkg, ver, scope, via) in js_matches_package_lock(content, deny_pairs, declared["js"]):
                    results.append(Match(org, repo_name, branch, path, eco, pkg, ver, base, scope, via))

            elif base == "yarn.lock":
                for (pkg, ver, scope) in js_matches_yarn_lock(content, deny_pairs, declared["js"]):
                    results.append(Match(org, repo_name, branch, path, eco, pkg, ver, base, scope))

        # Python
        elif base in PY_FILES and ecosystem in ("python", "all"):
            eco = "python"

            if base.lower().startswith("requirements"):
                for (pkg, ver, scope) in python_requirements_matches(content, deny_pairs):
                    results.append(Match(org, repo_name, branch, path, eco, pkg, ver, base, scope))

            elif base == "Pipfile.lock":
                for (pkg, ver, scope, via) in python_lock_matches(content, deny_pairs, declared["python"], flavor="pipfile"):
                    results.append(Match(org, repo_name, branch, path, eco, pkg, ver, base, scope, via))

            elif base == "poetry.lock":
                for (pkg, ver, scope, via) in python_lock_matches(content, deny_pairs, declared["python"], flavor="poetry"):
                    results.append(Match(org, repo_name, branch, path, eco, pkg, ver, base, scope, via))

            elif base == "pyproject.toml":
                for (pkg, ver, scope) in python_pyproject_direct(content, deny_pairs):
                    results.append(Match(org, repo_name, branch, path, eco, pkg, ver, base, scope))

        # PHP / Composer
        elif base in PHP_FILES and ecosystem in ("php", "all"):
            eco = "php"

            if base == "composer.json":
                try:
                    data = json.loads(content)
                except json.JSONDecodeError:
                    data = {}

                for section in ("require", "require-dev"):
                    deps = data.get(section, {}) or {}
                    for dn, dv in deny_pairs:
                        if dn in deps and str(deps[dn]).strip() == dv:
                            results.append(Match(org, repo_name, branch, path, eco, dn, dv, base, "direct"))

            elif base == "composer.lock":
                for (pkg, ver, scope, via) in composer_lock_matches(content, deny_pairs, declared["php"]):
                    results.append(Match(org, repo_name, branch, path, eco, pkg, ver, base, scope, via))

        # Java / Maven / Gradle
        elif base in JAVA_FILES and ecosystem in ("java", "all"):
            eco = "java"

            if base == "pom.xml":
                for (pkg, ver) in java_matches_pom_xml(content, deny_pairs):
                    results.append(Match(org, repo_name, branch, path, eco, pkg, ver, base, "direct"))

            elif base in ("build.gradle", "build.gradle.kts"):
                for (pkg, ver) in java_matches_gradle(content, deny_pairs):
                    results.append(Match(org, repo_name, branch, path, eco, pkg, ver, base, "direct"))

        # Go
        elif base in GO_FILES and ecosystem in ("go", "all"):
            eco = "go"

            if base == "go.mod":
                for (mod, ver, indirect) in declared["go_triplets"]:
                    scope = "transitive" if indirect else "direct"

                    for (den_n, den_v) in deny_pairs:
                        dvn = den_v.lstrip("v")
                        if den_n == mod and (ver == dvn or ver == f"v{dvn}"):
                            results.append(Match(org, repo_name, branch, path, eco, den_n, den_v, base, scope))

            elif base == "go.sum":
                present = go_sum_present(content)

                for (den_n, den_v) in deny_pairs:
                    dvn = den_v.lstrip("v")
                    if (den_n, dvn) in present or (den_n, f"v{dvn}") in present:
                        scope = "direct" if den_n in declared["go_names"] else "transitive"
                        results.append(Match(org, repo_name, branch, path, eco, den_n, den_v, base, scope))

        # Ruby / Bundler
        elif base in RUBY_FILES and ecosystem in ("ruby", "all"):
            eco = "ruby"

            if base == "Gemfile":
                for dn, dv in deny_pairs:
                    pat = re.compile(r'\bgem\s+["\']%s["\']\s*,\s*["\']%s["\']' % (re.escape(dn), re.escape(dv)))
                    if pat.search(content):
                        results.append(Match(org, repo_name, branch, path, eco, dn, dv, base, "direct"))

            elif base == "Gemfile.lock":
                parents, present = ruby_build_graph_gemfile_lock(content)
                deny_set = set(deny_pairs)

                for (name, ver) in present:
                    if (name, ver) not in deny_set:
                        continue

                    scope = "direct" if name in declared["ruby"] else "transitive"
                    via = ""

                    if scope == "transitive":
                        plist = sorted(parents.get((name, ver), set()))
                        if plist:
                            via = " | ".join([f"{pn}@{pv} -> {name}@{ver}" for (pn, pv) in plist])

                    results.append(Match(org, repo_name, branch, path, eco, name, ver, base, scope, via))

    return results


# CLI

def interactive_ecosystem_choice() -> str:
    """Prompt user to select ecosystem interactively."""
    options = ["js", "python", "php", "java", "go", "ruby", "all"]
    print("Wähle Ecosystem (Zahl):")
    for i, opt in enumerate(options, 1):
        print(f"  {i}) {opt}")

    while True:
        sel = input("> ").strip()
        if sel.isdigit() and 1 <= int(sel) <= len(options):
            return options[int(sel) - 1]
        print(f"Ungültig. Bitte 1-{len(options)} eingeben.")


def main():
    parser = argparse.ArgumentParser(
        description="GitHub Org dependency denylist auditor (graph-based provenance)"
    )
    parser.add_argument("org", help="GitHub organization name")
    parser.add_argument("denylist", help="Path to denylist (name@version; Java: group:artifact@version)")
    parser.add_argument("--ecosystem", choices=["js", "python", "php", "java", "go", "ruby", "all"],
                       help="Ecosystem to scan (default: prompt)")
    parser.add_argument("--include-archived", action="store_true",
                       help="Include archived repositories")
    parser.add_argument("--only-private", action="store_true",
                       help="Scan only private repositories")
    parser.add_argument("--only-public", action="store_true",
                       help="Scan only public repositories")
    parser.add_argument("--limit", type=int, default=0,
                       help="Limit repositories for testing")
    parser.add_argument("--out", default=DEFAULT_OUTPUT_FILE,
                       help=f"Ausgabedatei (.xlsx oder .csv). Standard: {DEFAULT_OUTPUT_FILE}")

    args = parser.parse_args()

    require_token()
    ecosystem = args.ecosystem or interactive_ecosystem_choice()
    deny_pairs = load_denylist(args.denylist)
    repos = get_org_repos(args.org)

    results: List[Match] = []
    scanned = 0

    for repo in repos:
        if not args.include_archived and repo.get("archived"):
            continue
        if args.only_private and not repo.get("private"):
            continue
        if args.only_public and repo.get("private"):
            continue

        name = repo["name"]
        branch = get_repo_default_branch(repo)
        print(f"→ Scanning {args.org}/{name}@{branch} ...")

        try:
            repo_results = audit_repo(args.org, name, branch, ecosystem, deny_pairs)
        except Exception as e:
            print(f"WARN: scan failed for {name}: {e}", file=sys.stderr)
            continue

        results.extend(repo_results)
        scanned += 1

        if args.limit and scanned >= args.limit:
            break

    # Group results by repository
    by_repo: Dict[str, List[Match]] = defaultdict(list)
    for m in results:
        by_repo[m.repo].append(m)

    # Print summary
    print("\nSUMMARY")
    print(f"Organization : {args.org}")
    print(f"Ecosystem    : {ecosystem}")
    print(f"Repos scanned: {scanned}")
    print(f"Matches found: {len(results)} in {len(by_repo)} repositories")

    for repo, matches in sorted(by_repo.items()):
        print(f"\n# {repo}")
        for m in matches:
            line = f"  - [{m.ecosystem}] {m.package}@{m.version}  ({m.scope}; {m.file_type}: {m.path})"
            if m.via:
                line += f"\n      via: {m.via}"
            print(line)

    # Export results
    out_path = args.out
    ext = os.path.splitext(out_path)[1].lower()

    try:
        write_results(results, out_path)
        format_name = "Excel" if ext == ".xlsx" else "CSV"
        print(f"\n{format_name} geschrieben: {out_path}")
    except Exception as e:
        print(f"WARN: Export nach '{out_path}' fehlgeschlagen: {e}", file=sys.stderr)
        fallback = "audit_results.csv"
        _write_csv(results, fallback)
        print(f"CSV-Fallback geschrieben: {fallback}")


if __name__ == "__main__":
    main()
