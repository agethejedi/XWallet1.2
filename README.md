X-Wallet Web v1.2 — Full Bundle
=================================
Includes a web frontend and a SafeSend stub backend.

Quick start
-----------
1) Backend (terminal A):
   cd safesend-server
   npm install
   npm start
   # SafeSend runs at http://localhost:3001/check

2) Frontend (terminal B):
   cd frontend
   # Edit js/app.js: set your Sepolia RPC URL (Alchemy/Infura/QuickNode)
   # Example: RPCS.sep = 'https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY'
   npx http-server -c-1   # or any static server
   # open http://127.0.0.1:8080 (or whichever port)

3) Use the app:
   - Create or Import a wallet -> Save vault with a password
   - Unlock -> app derives EVM address and connects to Sepolia
   - Fund address from a Sepolia faucet
   - Send tab -> enter recipient + amount (ETH) -> SafeSend runs -> tx broadcasts on Sepolia -> Etherscan link

Notes
-----
- Vault uses AES-GCM+PBKDF2 and is stored in localStorage.
- Messaging uses XMTP and needs recipient wallets on XMTP.
- Charts fetch from CoinGecko; for production proxy via backend.
- This is a developer build; harden before production and route RPC via a backend to protect keys.
