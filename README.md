"# DependencieBlacklistScannerForOrganisations" 

Usage: 
python3 -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt

export GITHUB_TOKEN=XXX (read only)

python dep_blacklistscanner.py <org-name> <denylist.txt> [--ecosystem all|js|python|php|java|go]



The example denylist containes all npm dep that where hit by the shai hulud 2 worm - Feel free to scan your Org
