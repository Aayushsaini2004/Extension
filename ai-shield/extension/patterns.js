// Sensitive data detectors. Sab kuch browser ke andar chalta hai - data kahin nahi jata.
const luhn = (s) => {
  const d = s.replace(/\D/g, ""); if (d.length < 13 || d.length > 19) return false;
  let sum = 0, alt = false;
  for (let i = d.length - 1; i >= 0; i--) { let n = +d[i]; if (alt) { n *= 2; if (n > 9) n -= 9; } sum += n; alt = !alt; }
  return sum % 10 === 0;
};
const PATTERNS = [
  { name: "AWS Access Key ID", sev: "HIGH", re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b/g },
  { name: "AWS Secret Access Key", sev: "HIGH", re: /aws.{0,25}(?:secret|sk).{0,10}[=:]\s*['"]?([A-Za-z0-9\/+=]{40})\b/gi, group: 1 },
  { name: "Private Key (PEM)", sev: "HIGH", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g },
  { name: "GitHub Token", sev: "HIGH", re: /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{30,}\b/g },
  { name: "Google API Key", sev: "HIGH", re: /\bAIza[0-9A-Za-z_\-]{35}\b/g },
  { name: "OpenAI / Anthropic API Key", sev: "HIGH", re: /\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{32,}\b/g },
  { name: "Stripe Secret Key", sev: "HIGH", re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b/g },
  { name: "Razorpay Key", sev: "HIGH", re: /\brzp_(?:live|test)_[A-Za-z0-9]{10,}\b/g },
  { name: "Slack Token", sev: "HIGH", re: /\bxox[abprs]-[A-Za-z0-9\-]{10,}\b/g },
  { name: "NPM Access Token", sev: "HIGH", re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { name: "Bearer Access Token", sev: "HIGH", re: /\bBearer\s+[A-Za-z0-9._~+\/-]{16,}={0,2}/gi },
  { name: "JWT Token", sev: "MEDIUM", re: /\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/g },
  { name: "DB Connection String with password", sev: "HIGH", re: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^\s:@\/]+:[^\s@\/]+@[^\s]+/gi },
  { name: "Hardcoded password / secret", sev: "MEDIUM", re: /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret|auth[_-]?token)\b\s*[=:]\s*["']?([^\s"'`,;]{6,})/gi, group: 1 },
  { name: "Credit/Debit Card Number", sev: "HIGH", re: /\b(?:\d[ \-]?){13,19}\b/g, validate: luhn },
  { name: "Aadhaar Number", sev: "HIGH", re: /\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b/g },
  { name: "PAN Card Number", sev: "HIGH", re: /\b[A-Z]{5}\d{4}[A-Z]\b/g },
  { name: "Bank account number", sev: "MEDIUM", re: /\b(?:account|a\/c)\D{0,15}\d{9,18}\b/gi },
  { name: "Email address", sev: "MEDIUM", re: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi },
  { name: "Phone number", sev: "MEDIUM", re: /\b(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3,5}\)?[\s.-]?)\d{5,8}\b/g }
];
const mask = (s) => s.length <= 8 ? "****" : s.slice(0, 4) + "…" + "*".repeat(4) + s.slice(-2);

function scanText(text) {
  const out = [];
  if (!text) return out;
  for (const p of PATTERNS) {
    p.re.lastIndex = 0; let m, count = 0, sample = "";
    while ((m = p.re.exec(text))) {
      const v = p.group ? m[p.group] : m[0];
      if (m.index === p.re.lastIndex) p.re.lastIndex++;
      if (p.validate && !p.validate(v)) continue;
      if (!count) sample = mask(v.trim()); count++;
    }
    if (count) out.push({ name: p.name, sev: p.sev, count, sample });
  }
  return out;
}
