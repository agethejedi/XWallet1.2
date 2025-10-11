// worker.js — SafeSend + Market Price Worker by RiskXLabs

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const origin = req.headers.get("Origin") || "";

    // CORS preflight
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (url.pathname === "/health") {
      return json({ ok: true, build: "safesend-cloudflare-v2.0" }, 200, origin);
    }

    if (url.pathname === "/check") {
      return handleCheck(url, env, origin);
    }

    if (url.pathname === "/market/price") {
      return handlePrice(url, env, origin);
    }

    return new Response("Not Found", { status: 404, headers: corsHeaders(origin) });
  },
};

/* ----------------------------- Helpers ----------------------------- */

function corsHeaders(origin) {
  // Allow your GitHub Pages origin + local dev
  const ALLOW = new Set([
    "https://agethejedi.github.io",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
  ]);

  const allowed = origin && ALLOW.has(origin);
  return {
    "Access-Control-Allow-Origin": allowed ? origin : "https://agethejedi.github.io",
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  };
}

function json(data, status = 200, origin = "") {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", ...corsHeaders(origin) },
  });
}

/* ---------------------------- /check ------------------------------- */
/* SafeSend risk evaluator backed by Etherscan-style explorers */
async function handleCheck(url, env, origin) {
  const address = (url.searchParams.get("address") || "").toLowerCase();
  const chain   = (url.searchParams.get("chain") || "sepolia").toLowerCase();

  if (!address.startsWith("0x")) return json({ error: "address required" }, 400, origin);

  const HOSTS = {
    sepolia: "api-sepolia.etherscan.io",
    mainnet: "api.etherscan.io",
    polygon: "api.polygonscan.com",
  };
  const host = HOSTS[chain] || HOSTS.sepolia;

  const blocklist = new Set(["0x000000000000000000000000000000000000dead"]);
  const allowlist = new Set();

  if (blocklist.has(address))
    return json({ score: 95, findings: ["Blocklist match: known scam"] }, 200, origin);
  if (allowlist.has(address))
    return json({ score: 5, findings: ["Allowlist: known good address"] }, 200, origin);

  let score = 20;
  const findings = [];

  // 1) Contract code check
  try {
    const codeUrl = `https://${host}/api?module=proxy&action=eth_getCode&address=${address}&tag=latest&apikey=${env.ETHERSCAN_API_KEY}`;
    const codeRes = await fetch(codeUrl);
    const code = await codeRes.json();
    if (code?.result && code.result !== "0x") {
      score += 30;
      findings.push("Address is a contract");
    }
  } catch {
    findings.push("Etherscan code check failed");
  }

  // 2) Transaction age
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
  } catch {
    findings.push("Etherscan tx fetch failed");
  }

  score = Math.max(0, Math.min(100, score));
  return json({ score, findings }, 200, origin);
}

/* ------------------------- /market/price --------------------------- */
/* Batch CoinGecko simple/price with 60s edge caching + CORS */
async function handlePrice(url, env, origin) {
  const ids  = (url.searchParams.get("ids") || "bitcoin,ethereum").toLowerCase();
  const vs   = (url.searchParams.get("vs")  || "usd").toLowerCase();
  const chg  = (url.searchParams.get("change") || "true").toLowerCase();

  const cgUrl = `https://api.coingecko.com/api/v3/simple/price` +
                `?ids=${encodeURIComponent(ids)}` +
                `&vs_currencies=${encodeURIComponent(vs)}` +
                `&include_24hr_change=${encodeURIComponent(chg)}`;

  const headers = {};
  if (env.COINGECKO_API_KEY) headers["x-cg-pro-api-key"] = env.COINGECKO_API_KEY;

  try {
    const res = await fetch(cgUrl, {
      headers,
      cf: { cacheTtl: 60, cacheEverything: true },
    });
    if (!res.ok) {
      return new Response(JSON.stringify({ error: "coingecko_failed", status: res.status }), {
        status: res.status,
        headers: { "content-type": "application/json", ...corsHeaders(origin) },
      });
    }
    const data = await res.json();
    return new Response(JSON.stringify(data), {
      status: 200,
      headers: {
        "content-type": "application/json",
        ...corsHeaders(origin),
        "Cache-Control": "public, max-age=60",
      },
    });
  } catch (e) {
    return json({ error: "market_fetch_failed", message: e.message }, 500, origin);
  }
}
