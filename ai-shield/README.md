# AI Shield

AI Shield is a free Manifest V3 browser extension that warns about sensitive
data before it is sent to supported AI chat sites. Text detection and OCR run
locally in your browser. No account, payment, license key, or server is needed.

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
