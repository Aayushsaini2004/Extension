let offscreenDocumentPromise;

async function ocr(dataUrl) {
  if (!(await chrome.offscreen.hasDocument())) {
    if (!offscreenDocumentPromise) {
      offscreenDocumentPromise = chrome.offscreen.createDocument({
        url: "offscreen.html", reasons: ["WORKERS"], justification: "On-device OCR"
      }).catch(async (error) => {
        if (!(await chrome.offscreen.hasDocument())) throw error;
      }).finally(() => { offscreenDocumentPromise = null; });
    }
    await offscreenDocumentPromise;
  }
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ target: "offscreen", dataUrl }, (result) => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else if (result?.error) reject(new Error(result.error));
      else resolve(result);
    });
  });
}
chrome.runtime.onMessage.addListener((msg, _s, send) => {
  if (msg.target === "offscreen") return;
  (async () => {
    if (msg.type === "status") send({ active: true, free: true });
    else if (msg.type === "ocr") send(await ocr(msg.dataUrl));
  })().catch((error) => {
    console.error("AI Shield background request failed:", error);
    send({ active: false, error: error.message || "AI Shield request failed" });
  });
  return true;
});
