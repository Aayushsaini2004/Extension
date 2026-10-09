const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const context = {};
const source = fs.readFileSync(path.join(__dirname, "..", "patterns.js"), "utf8");
vm.runInNewContext(`${source}\nglobalThis.scanTextForTest = scanText;`, context);
const scan = (text) => JSON.parse(JSON.stringify(context.scanTextForTest(text)));

test("detects common API keys and unquoted secret assignments", () => {
  const findings = scan("AWS key AKIA1234567890ABCDEF; password=sample-secret-123; npm_123456789012345678901234567890123456");
  assert.ok(findings.some((item) => item.name === "AWS Access Key ID"));
  assert.ok(findings.some((item) => item.name === "Hardcoded password / secret"));
  assert.ok(findings.some((item) => item.name === "NPM Access Token"));
});

test("detects personal identifiers in text and OCR output", () => {
  const findings = scan("PAN ABCDE1234F, Aadhaar 2345 6789 0123, email test@example.com");
  assert.ok(findings.some((item) => item.name === "PAN Card Number"));
  assert.ok(findings.some((item) => item.name === "Aadhaar Number"));
  assert.ok(findings.some((item) => item.name === "Email address"));
});

test("validates payment card numbers instead of flagging arbitrary digit strings", () => {
  assert.ok(scan("4111 1111 1111 1111").some((item) => item.name === "Credit/Debit Card Number"));
  assert.ok(!scan("4111 1111 1111 1112").some((item) => item.name === "Credit/Debit Card Number"));
});

test("returns no findings for ordinary text", () => {
  assert.deepEqual(scan("Please summarize this public article for me."), []);
});
