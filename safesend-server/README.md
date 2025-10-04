SafeSend Stub Server
=====================
Runs a tiny Express service that scores recipient addresses.

Usage:
  cd safesend-server
  npm install
  npm start

Endpoint:
  GET /check?address=0x... -> { score, findings }

Scoring (demo):
  - Blocklist address -> score 95 (blocked by frontend if >70)
  - Allowlist address -> score 5 (low risk)
  - Others -> random 20..79 with basic findings

Customize:
  - Replace scoring logic with your data sources (Etherscan, heuristics, etc.).
