#!/bin/bash
# Connect a Yellowstone Plumbing mailbox to the quantumcrew-mail MCP.
#
#   ./reauth_yellowstone.sh josh@yellowstoneplumbing.com
#
# Verified 2026-08-27: yellowstoneplumbing.com MX = smtp.google.com (Google Workspace)
# and SPF includes _spf.google.com — so this mailbox can be authorised here and mail
# sent from it is already SPF-aligned. No DNS work needed.
#
# ⚠️ JOSH has to be at the browser for this. It's his Google password and his consent
# screen. Devin cannot complete it on his behalf.

set -euo pipefail
cd "$(dirname "$0")"

EMAIL="${1:-}"
if [ -z "$EMAIL" ]; then
  echo "usage: ./reauth_yellowstone.sh josh@yellowstoneplumbing.com"
  exit 1
fi

# --- add to .accounts.json if not already there (idempotent)
.venv/bin/python - "$EMAIL" <<'PY'
import json, sys
email = sys.argv[1]
p = ".accounts.json"
d = json.load(open(p))
if any(a.get("email") == email for a in d["accounts"]):
    print(f"  {email} already in .accounts.json")
else:
    d["accounts"].append({
        "email": email,
        "account_type": "work",
        "extra_info": ("Josh Chasteen — owner, Yellowstone Plumbing & Drains (Chandler AZ). "
                       "CLIENT mailbox, not QuantumCrew's. Used for owner-to-owner partner "
                       "outreach. Never send from here without Josh's explicit approval of "
                       "the specific message."),
    })
    json.dump(d, open(p, "w"), indent=2)
    print(f"  added {email} to .accounts.json")
PY

# Port 4100 can linger in TIME_WAIT with no owning process — test a real bind.
free_port() {
  for _ in $(seq 1 60); do
    pids=$(lsof -ti:4100 2>/dev/null) && [ -n "$pids" ] && kill -9 $pids 2>/dev/null || true
    if .venv/bin/python -c "import socket;s=socket.socket();s.bind(('127.0.0.1',4100));s.close()" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
}

echo ""
echo "=================================================="
echo "  Authorising: $EMAIL"
echo ""
echo "  A browser window is about to open."
echo "  JOSH signs in and clicks Allow."
echo "=================================================="
echo ""
free_port

.venv/bin/python -c "
import sys
sys.path.insert(0, 'src')
sys.argv = ['', '--credentials-dir', '.', '--accounts-file', '.accounts.json', '--gauth-file', '.gauth.json']
from mcp_gsuite.gauth import run_oauth_flow
run_oauth_flow('$EMAIL')
print('DONE — $EMAIL authorised')
"

echo ""
echo "Restart Claude Code so the MCP picks up the new account."
