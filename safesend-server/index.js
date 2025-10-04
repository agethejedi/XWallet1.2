import express from "express";
import cors from "cors";
import fetch from "node-fetch";
import dotenv from "dotenv";

dotenv.config();
const app = express();
app.use(cors());

const PORT = process.env.PORT || 3001;
const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY;

// Demo lists
const blocklist = new Set([
  "0x000000000000000000000000000000000000dead"
]);
const allowlist = new Set([
  // add addresses you trust
]);

app.get("/check", async (req, res) => {
  const address = (req.query.address || "").toLowerCase();
  if (!address.startsWith("0x")) {
    return res.status(400).json({ error: "address required" });
  }

  let score = 20;
  const findings = [];

  // Block/allow quick check
  if (blocklist.has(address)) {
    return res.json({ score: 95, findings: ["Blocklist match: known scam"] });
  }
  if (allowlist.has(address)) {
    return res.json({ score: 5, findings: ["Allowlist: low risk"] });
  }

  try {
    // === 1) Check if it's a contract ===
    const codeResp = await fetch(
      `https://api-sepolia.etherscan.io/api?module=proxy&action=eth_getCode&address=${address}&tag=latest&apikey=${ETHERSCAN_API_KEY}`
    );
    const code = await codeResp.json();
    if (code.result && code.result !== "0x") {
      score += 30;
      findings.push("Address is a contract");
    }

    // === 2) Transaction history ===
    const txResp = await fetch(
      `https://api-sepolia.etherscan.io/api?module=account&action=txlist&address=${address}&startblock=0&endblock=99999999&sort=asc&apikey=${ETHERSCAN_API_KEY}`
    );
    const txData = await txResp.json();

    if (txData.status === "1") {
      if (txData.result.length === 0) {
        score += 30;
        findings.push("No transactions (new account)");
      } else {
        const firstTx = txData.result[0];
        const age = Date.now() / 1000 - Number(firstTx.timeStamp);
        if (age < 86400 * 2) {
          score += 20;
          findings.push("Very new address (<2 days old)");
        } else {
          findings.push("Address has history");
        }
      }
    } else {
      findings.push("Etherscan returned no tx data");
    }
  } catch (e) {
    console.error("SafeSend error:", e);
    findings.push("Error querying Etherscan");
  }

  // Bound score 0–100
  score = Math.min(100, Math.max(0, score));

  res.json({ score, findings });
});

app.listen(PORT, () => {
  console.log(`✅ SafeSend running on http://localhost:${PORT}`);
});

