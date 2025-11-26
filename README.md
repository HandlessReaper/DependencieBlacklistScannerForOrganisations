"# DependencieBlacklistScannerForOrganisations" 

Usage: 
python3 -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt

export GITHUB_TOKEN=XXX (read only)

python github_dep_quickscan.py <org-name> <denylist.txt> [--ecosystem all|js|python|php|java|go]