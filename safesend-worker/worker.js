// worker.js — SafeSend Worker by RiskXLabs
export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);

    // Handle CORS preflight
    if (req.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders(url.origin) });
    }

    if (url.pathname === "/health") {
      return json({ ok: true, build: "safesend-cloudflare-v1.0" });
    }

    if (url.pathname === "/check") return handleCheck(url, env);
    if (url.pathname === "/market/chart") return handleMarket(url, env);

    return new Response("Not Found", { status: 404, headers: corsHeaders(url.origin) });
  },
};

// ---- Helpers ----
function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin || "*", // Replace * with your GitHub Pages domain for security
    "Access-Control-Allow-Methods": "GET,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

function json(data, status = 200, origin = "*") {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", ...corsHeaders(origin) },
  });
}

// ---- /check (SafeSend risk evaluator) ----
async function handleCheck(url, env) {
  const address = (url.searchParams.get("address") || "").toLowerCase();
  const chain = (url.searchParams.get("chain") || "sepolia").toLowerCase();

  if (!address.startsWith("0x")) return json({ error: "address required" }, 400);

  const HOSTS = {
    sepolia: "api-sepolia.etherscan.io",
    mainnet: "api.etherscan.io",
    polygon: "api.polygonscan.com",
  };
  const host = HOSTS[chain] || HOSTS.sepolia;

  const blocklist = new Set(["0x000000000000000000000000000000000000dead"]);
  const allowlist = new Set();

  if (blocklist.has(address))
    return json({ score: 95, findings: ["Blocklist match: known scam"] });
  if (allowlist.has(address))
    return json({ score: 5, findings: ["Allowlist: known good address"] });

  let score = 20;
  const findings = [];

  // 1. Contract code check
  try {
    const codeUrl = `https://${host}/api?module=proxy&action=eth_getCode&address=${address}&tag=latest&apikey=${env.ETHERSCAN_API_KEY}`;
    const codeRes = await fetch(codeUrl);
    const code = await codeRes.json();
    if (code?.result && code.result !== "0x") {
      score += 30;
      findings.push("Address is a contract");
    }
  } catch (e) {
    findings.push("Etherscan code check failed");
  }

  // 2. Transaction age
  try {
    const txUrl = `https://${host}/api?module=account&action=txlist&address=${address}&startblock=0&endblock=99999999&sort=asc&apikey=${env.ETHERSCAN_API_KEY}`;
    const txRes = await fetch(txUrl);
    const txs = await txRes.json();
    if (txs.status === "1") {
      const list = txs.result || [];
      if (list.length === 0) {
        score += 30;
        findings.push("New address — no transaction history");
      } else {
        const first = list[0];
        const ageSec = Date.now() / 1000 - Number(first.timeStamp || 0);
        if (ageSec < 48 * 3600) {
          score += 20;
          findings.push("Very new address (<2 days)");
        } else {
          findings.push("Has transaction history");
        }
      }
    } else {
      findings.push("Explorer returned no tx data");
    }
  } catch (e) {
    findings.push("Etherscan tx fetch failed");
  }

  score = Math.max(0, Math.min(100, score));
  return json({ score, findings });
}

// ---- /market/chart (CoinGecko proxy) ----
async function handleMarket(url, env) {
  const id = (url.searchParams.get("id") || "ethereum").toLowerCase();
  const days = url.searchParams.get("days") || "1";
  const interval = url.searchParams.get("interval") || "minute";

  const cgUrl = `https://api.coingecko.com/api/v3/coins/${encodeURIComponent(
    id
  )}/market_chart?vs_currency=usd&days=${encodeURIComponent(
    days
  )}&interval=${encodeURIComponent(interval)}`;

  const headers = {};
  if (env.COINGECKO_API_KEY) headers["x-cg-pro-api-key"] = env.COINGECKO_API_KEY;

  try {
    const res = await fetch(cgUrl, {
      headers,
      cf: { cacheTtl: 60, cacheEverything: true },
    });
    if (!res.ok) return json({ error: "coingecko_failed", status: res.status }, res.status);
    const data = await res.json();
    return new Response(JSON.stringify(data), {
      status: 200,
      headers: {
        "content-type": "application/json",
        ...corsHeaders("*"),
        "Cache-Control": "public, max-age=60",
      },
    });
  } catch (e) {
    return json({ error: "market_fetch_failed", message: e.message }, 500);
  }
}
