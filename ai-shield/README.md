# AI Shield

AI Shield is a free Manifest V3 browser extension that warns about sensitive
data before it is sent to supported AI chat sites. Text detection and OCR run
locally in your browser. No account, payment, license key, or server is needed.

When sensitive text is pasted or found as you submit a prompt, choose the
**1-Click Neutralize** button to replace detected values with contextual
placeholders in the composer. On the submit warning, **1-Click Neutralize &
Send** also sends the sanitized prompt. Detected sensitive content in an image
cannot be rewritten in place, so review or remove that attachment before
proceeding. Credential assignment names such as `API_KEY`, `OPENAI_API_KEY`,
`ACCESS_TOKEN`, and `CLIENT_SECRET` are detected across providers without
requiring a provider-specific token format. Arbitrary unlabeled strings cannot
always be identified reliably as API keys.

## Requirements

- Chrome or another Chromium-based browser

## Load the browser extension

1. Open `chrome://extensions` (or the equivalent extensions page in your
   Chromium-based browser).
2. Enable **Developer mode**.
3. Select **Load unpacked** and choose the project's `extension` directory.
4. Visit a supported AI chat site and use the AI Shield toolbar icon to confirm
   the extension is active.

Supported sites include ChatGPT, Claude, Gemini, Perplexity, Copilot,
DeepSeek, Grok, Mistral, Poe, You.com, and Hugging Face Chat.

## Run detector tests

From the project root, run:

```powershell
npm test
```

OCR runtime files are bundled in `extension/lib`. The optional `setup.sh`
script can rebuild those files on systems with Bash and npm.

## Project layout

- `extension/` — browser extension source, detector tests, and bundled OCR
  runtime
- `setup.sh` — optional script for rebuilding the bundled OCR runtime
