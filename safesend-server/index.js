import express from "express";
import cors from "cors";
import fetch from "node-fetch";
import dotenv from "dotenv";

dotenv.config();
const app = express();
app.use(cors());

const PORT = process.env.PORT || 3001;
const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY;

// Map chain -> explorer API host
const HOST = {
  sepolia: "api-sepolia.etherscan.io",
  mainnet: "api.etherscan.io",
  polygon: "api.polygonscan.com" // same API shape
};

// Simple lists you control
const blocklist = new Set(["0x000000000000000000000000000000000000dead"]);
const allowlist = new Set([]);

// Helper to call *scan
async function scan(host, pathAndQuery) {
  const url = `https://${host}/api${pathAndQuery}&apikey=${ETHERSCAN_API_KEY}`;
  const r = await fetch(url);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

/**
 * GET /check?address=0x...&chain=sepolia|mainnet|polygon
 * Returns: { score: 0..100, findings: string[] }
 */
app.get("/check", async (req, res) => {
  try {
    const address = (req.query.address || "").toLowerCase();
    const chain = (req.query.chain || "sepolia").toLowerCase();
    const host = HOST[chain] || HOST.sepolia;

    if (!address.startsWith("0x")) {
      return res.status(400).json({ error: "address required" });
    }

    // Quick allow/block
    if (blocklist.has(address)) {
      return res.json({ score: 95, findings: ["Blocklist match: known scam"] });
    }
    if (allowlist.has(address)) {
      return res.json({ score: 5, findings: ["Allowlist: low risk"] });
    }

    let score = 20;        // start neutral/low
    const findings = [];

    // 1) Is contract?
    const code = await scan(host, `?module=proxy&action=eth_getCode&address=${address}&tag=latest`);
    if (code?.result && code.result !== "0x") {
      score += 30;
      findings.push("Address is a contract");
    }

    // 2) TX history (first tx -> age/newness)
    const txs = await scan(
      host,
      `?module=account&action=txlist&address=${address}&startblock=0&endblock=99999999&sort=asc`
    );

    if (txs.status === "1") {
      const list = txs.result || [];
      if (list.length === 0) {
        score += 30;
        findings.push("No transactions (new account)");
      } else {
        const first = list[0];
        const ageSec = Date.now() / 1000 - Number(first.timeStamp || 0);
        if (ageSec < 2 * 24 * 3600) {
          score += 20;
          findings.push("Very new address (< 2 days)");
        } else {
          findings.push("Has transaction history");
        }
      }
    } else {
      findings.push("Explorer returned no tx data");
    }

    // 3) Optional: internal txs hint (new/empty)
    try {
      const internals = await scan(
        host,
        `?module=account&action=txlistinternal&address=${address}&startblock=0&endblock=99999999&sort=asc`
      );
      if (internals.status === "1" && internals.result.length === 0) {
        findings.push("No internal txs (info)");
      }
    } catch { /* ignore */ }

    // Clamp score 0..100
    score = Math.max(0, Math.min(100, score));
    return res.json({ score, findings });
  } catch (e) {
    console.error("SafeSend error:", e);
    return res.status(500).json({ score: 50, findings: ["SafeSend backend error", String(e.message || e)] });
  }
});

app.listen(PORT, () => {
  console.log(`✅ SafeSend running on http://localhost:${PORT}`);
});
