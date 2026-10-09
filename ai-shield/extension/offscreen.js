let workerP;
const getWorker = () => (workerP ||= Tesseract.createWorker("eng", 1, {
  workerPath: "lib/worker.min.js", corePath: "lib/", langPath: "lib/", workerBlobURL: false, gzip: true }));
chrome.runtime.onMessage.addListener((msg, _s, send) => {
  if (msg.target !== "offscreen") return;
  getWorker()
    .then((w) => w.recognize(msg.dataUrl))
    .then((r) => send({ text: r.data.text }))
    .catch((error) => send({ error: error.message || "OCR failed" }));
  return true;
});
