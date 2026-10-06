#!/usr/bin/env bash
# Install ODIVORA API server on Ubuntu 22.04/24.04
set -euo pipefail

REPO_DIR=${REPO_DIR:-/opt/odivora}
API_BIND=${API_BIND:-0.0.0.0:8000}

sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip

cd "$REPO_DIR"
python3 -m venv venv
./venv/bin/pip install -r requirements.txt

# Configure environment once
if [ ! -f .env ]; then
  cp .env.example .env
  echo ">>> Edit $REPO_DIR/.env now (SECRET_KEY, DATABASE_URL, RELAY_*)."
fi

# Database schema (SQLite default; use psql for Postgres)
if [ -f odivora_home.db ] || grep -q 'sqlite' .env; then
  for f in migrations/00*.sql; do
    echo "applying $f"
    ./venv/bin/python - "$f" <<'PY'
import sqlite3, sys
c = sqlite3.connect("odivora_home.db")
ok, skipped = 0, 0
for line in open(sys.argv[1]):
    s = line.strip()
    # Data migrations (e.g. purging leaked secrets) are UPDATE statements, so
    # they must run too - skipping them silently keeps the secrets in place.
    if s.startswith(("ALTER", "CREATE", "UPDATE")):
        try:
            c.execute(s.rstrip(";")); ok += 1
        except Exception as e:
            # Re-running a migration is normal (columns may already exist).
            skipped += 1
            print(f"  skip: {s[:60]}... ({e})")
c.commit()
print(f"applied {ok} statements ({skipped} skipped)")
PY
  done
fi

sudo cp deploy/odivora-api.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now odivora-api
echo "API server on $API_BIND — check: curl -s http://127.0.0.1:8000/health"
