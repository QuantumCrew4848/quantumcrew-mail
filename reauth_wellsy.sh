#!/bin/bash
cd ~/projects/quantumcrew/quantumcrew-mail
echo "=============================="
echo "  Authorizing marketing@wellsymd.com"
echo "  A browser will open — sign in AS WELLSY (marketing@wellsymd.com) and click Allow"
echo "=============================="
.venv/bin/python -c "
import sys
sys.path.insert(0, 'src')
sys.argv = ['', '--credentials-dir', '.', '--accounts-file', '.accounts.json', '--gauth-file', '.gauth.json']
from mcp_gsuite.gauth import run_oauth_flow
run_oauth_flow('marketing@wellsymd.com')
print('DONE - marketing@wellsymd.com authorized')
"
