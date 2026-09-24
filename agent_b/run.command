#!/bin/zsh
set -euo pipefail
cd "${0:A:h}"
exec /usr/bin/python3 -m agent_b_harness.server
