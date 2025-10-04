X-Wallet Web v1.2 — Frontend
==============================
1) Edit js/app.js:
   - Set RPCS.sep to your Sepolia RPC URL (Alchemy/Infura/QuickNode).
   - Set SAFE_SEND_URL to your SafeSend checker endpoint (or run the stub in ../safesend-server).
2) Serve frontend over HTTPS or localhost dev server.
3) Flow:
   - Dashboard: Create/Import -> Save vault with password.
   - Unlock: enter password (locks after 10 min idle).
   - Send: enters recipient + amount, SafeSend runs, tx broadcast on Sepolia, link to Etherscan.
   - Messaging: XMTP chat with wallets on XMTP.
   - Markets: live mini-charts via CoinGecko.
