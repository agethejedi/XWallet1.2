import express from 'express';
import cors from 'cors';

const app = express();
app.use(cors());

const PORT = process.env.PORT || 3001;

// Demo lists
const blocklist = new Set([
  '0x000000000000000000000000000000000000dead'
]);
const allowlist = new Set([
  // Add addresses you trust for low risk
]);

app.get('/check', (req, res) => {
  const address = (req.query.address || '').toLowerCase();
  if (!address || !address.startsWith('0x')) {
    return res.status(400).json({ error: 'address required' });
  }
  if (blocklist.has(address)) {
    return res.json({ score: 95, findings: ['Blocklist match: known scam'] });
  }
  if (allowlist.has(address)) {
    return res.json({ score: 5, findings: ['Allowlist: low risk'] });
  }
  // Simple baseline score for demo
  const score = Math.floor(Math.random() * 60) + 20; // 20..79
  const findings = ['Not in blocklist', 'No ENS (demo)'];
  return res.json({ score, findings });
});

app.listen(PORT, () => {
  console.log(`SafeSend stub on http://localhost:${PORT}`);
});
