const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const context = {};
const source = fs.readFileSync(path.join(__dirname, "..", "patterns.js"), "utf8");
vm.runInNewContext(`${source}\nglobalThis.scanTextForTest = scanText; globalThis.neutralizeTextForTest = neutralizeText;`, context);
const scan = (text) => JSON.parse(JSON.stringify(context.scanTextForTest(text)));
const neutralize = (text) => JSON.parse(JSON.stringify(context.neutralizeTextForTest(text)));

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

test("neutralizes AWS keys while preserving the rest of the prompt", () => {
  const prompt = "Explain why this key fails: AKIAIOSFODNN7EXAMPLE in my config.";
  const result = neutralize(prompt);
  assert.equal(result.changed, true);
  assert.equal(result.text, "Explain why this key fails: [AWS_SECRET_KEY_1] in my config.");
  assert.equal(scan(result.text).length, 0);
});

test("neutralizes repeated secrets with distinct placeholders", () => {
  const result = neutralize("Use AKIAIOSFODNN7EXAMPLE then AKIAIOSFODNN7EXAMPLF.");
  assert.equal(result.text, "Use [AWS_SECRET_KEY_1] then [AWS_SECRET_KEY_2].");
});

test("neutralizes the complete private key block and preserves its context", () => {
  const prompt = "Check this key:\n-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----\nThanks";
  const result = neutralize(prompt);
  assert.equal(result.text, "Check this key:\n[PRIVATE_KEY_1]\nThanks");
  assert.equal(result.text.includes("private-material"), false);
});

test("neutralizes bank account digits without removing their explanation", () => {
  const result = neutralize("The account number is 123456789012.");
  assert.equal(result.text, "The account number is [BANK_ACCOUNT_1].");
});

test("neutralizes AWS environment and Java config values while preserving prompt context", () => {
  const accessKey = "AKIA" + "A".repeat(16);
  const secretKey = "B".repeat(40);
  const prompt = [
    "Here is my AWS configuration:",
    `AWS_ACCESS_KEY_ID=${accessKey}`,
    `AWS_SECRET_ACCESS_KEY=${secretKey}`,
    "Bucket Name: example-bucket",
    "",
    "Sample Java code:",
    `private String accessKey = "${accessKey}";`,
    "Please explain the config."
  ].join("\n");
  const result = neutralize(prompt);

  assert.equal(result.text, [
    "Here is my AWS configuration:",
    "AWS_ACCESS_KEY_ID=[AWS_SECRET_KEY_1]",
    "AWS_SECRET_ACCESS_KEY=[AWS_SECRET_KEY_2]",
    "Bucket Name: example-bucket",
    "",
    "Sample Java code:",
    'private String accessKey = "[AWS_SECRET_KEY_3]";',
    "Please explain the config."
  ].join("\n"));
});

test("detects and neutralizes API keys and credentials from different providers", () => {
  const prompt = [
    "OpenAI: OPENAI_API_KEY=sk-example-openai-key-123",
    "Gemini: GEMINI_API_KEY: gemini-example-key-456",
    "Custom service: MY_SERVICE_ACCESS_TOKEN=service-token-example-789",
    "Java config: private String clientSecret = \"client-secret-example-012\";",
    "This ordinary word is not a credential: monkey = banana"
  ].join("\n");
  const result = neutralize(prompt);

  assert.equal(result.text, [
    "OpenAI: OPENAI_API_KEY=[API_KEY_1]",
    "Gemini: GEMINI_API_KEY: [API_KEY_2]",
    "Custom service: MY_SERVICE_ACCESS_TOKEN=[API_KEY_3]",
    "Java config: private String clientSecret = \"[API_KEY_4]\";",
    "This ordinary word is not a credential: monkey = banana"
  ].join("\n"));
  assert.equal(result.changed, true);
});

test("detects generic API key assignments without depending on token format", () => {
  const findings = scan("API_KEY=custom-format-1234567890");
  assert.ok(findings.some((item) => item.name === "API Key / Credential" && item.sev === "HIGH"));
});
