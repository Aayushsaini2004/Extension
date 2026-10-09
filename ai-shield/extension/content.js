(() => {
  let active = false, bypass = false, checkingSend = false;
  const pendingImages = new Set();
  const refresh = () => chrome.runtime.sendMessage({ type: "status" }, (r) => { active = !!(r && r.active); });
  refresh(); setInterval(refresh, 60000);

  // ---------- Popup UI (Shadow DOM, page CSS se safe) ----------
  function showAlert({ title, findings, onProceed, onNeutralize, neutralizeLabel, onCancel }) {
    document.getElementById("ai-shield-host")?.remove();
    const host = document.createElement("div"); host.id = "ai-shield-host";
    const root = host.attachShadow({ mode: "open" });
    const style = document.createElement("style");
    style.textContent = `.bg{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif}
    .box{background:#fff;color:#111;border-radius:14px;padding:22px;width:min(460px,92vw);box-shadow:0 20px 60px rgba(0,0,0,.4)}
    h2{margin:0 0 4px;font-size:18px;color:#b91c1c}p{margin:0 0 12px;font-size:13px;color:#555}
    ul{list-style:none;margin:0 0 16px;padding:0;max-height:220px;overflow:auto}
    li{padding:8px 10px;border:1px solid #eee;border-radius:8px;margin-bottom:6px;font-size:13px;display:flex;justify-content:space-between;gap:8px}
    code{background:#f3f4f6;padding:1px 5px;border-radius:4px}.HIGH{color:#b91c1c;font-weight:700}.MEDIUM{color:#b45309;font-weight:700}
    .row{display:flex;gap:8px;justify-content:flex-end}button{border:0;border-radius:8px;padding:9px 14px;font-size:13px;cursor:pointer}
    .ok{background:#111;color:#fff}.neutralize{background:#2563eb;color:#fff}.no{background:#e5e7eb}`;
    const bg = document.createElement("div"); bg.className = "bg";
    const box = document.createElement("div"); box.className = "box";
    const h = document.createElement("h2"); h.textContent = "⚠️ " + title;
    const p = document.createElement("p");
    p.textContent = onNeutralize
      ? "Sensitive values ko placeholders se replace karke sanitized prompt bhej sakte hain."
      : title.includes("scan nahi ho paya")
      ? "Image ko check nahi kar paye. Cancel karke dobara try karein, ya risk samajh kar proceed karein."
      : "AI Shield ne ye sensitive content detect kiya:";
    const ul = document.createElement("ul");
    for (const f of findings) {
      const li = document.createElement("li");
      const l = document.createElement("span"); l.textContent = `${f.name} ×${f.count}  `;
      const c = document.createElement("code"); c.textContent = f.sample; l.appendChild(c);
      const s = document.createElement("span"); s.className = f.sev; s.textContent = f.sev;
      li.append(l, s); ul.appendChild(li);
    }
    const row = document.createElement("div"); row.className = "row";
    const cancel = document.createElement("button"); cancel.className = "no"; cancel.textContent = onProceed ? "Cancel / Edit" : "OK";
    cancel.onclick = () => { host.remove(); onCancel?.(); }; row.appendChild(cancel);
    if (onNeutralize) {
      const neutralize = document.createElement("button");
      neutralize.className = "neutralize";
      neutralize.textContent = neutralizeLabel || "1-Click Neutralize & Send";
      neutralize.onclick = () => { host.remove(); onNeutralize(); };
      row.appendChild(neutralize);
    }
    if (onProceed) {
      const go = document.createElement("button"); go.className = "ok"; go.textContent = "Phir bhi bhejo";
      go.onclick = () => { host.remove(); onProceed(); }; row.appendChild(go);
    }
    box.append(h, p, ul, row); bg.appendChild(box); root.append(style, bg);
    (document.documentElement || document).appendChild(host);
  }

  // ---------- Text scan on send ----------
  const composerOf = (from) =>
    from?.closest?.("textarea,[contenteditable='true']") ||
    from?.closest?.("form")?.querySelector("textarea,[contenteditable='true']") ||
    document.querySelector("textarea,[contenteditable='true']");
  const textOf = (el) => (el ? ("value" in el ? el.value : el.innerText) : "");
  const neutralizeComposer = (composer) => {
    if (!composer) return false;
    const result = neutralizeText(textOf(composer));
    if (!result.changed) return false;
    if ("value" in composer) {
      const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(composer), "value")?.set;
      if (setter) setter.call(composer, result.text);
      else composer.value = result.text;
    } else {
      composer.innerText = result.text;
    }
    composer.dispatchEvent(new InputEvent("input", {
      bubbles: true,
      inputType: "insertReplacementText",
      data: null
    }));
    return true;
  };
  const isSendBtn = (b) => b && /send|submit|ask/i.test(
    (b.getAttribute("aria-label") || "") + (b.getAttribute("data-testid") || "") +
    (b.getAttribute("title") || "") + (b.type === "submit" ? "submit" : ""));

  const imageFiles = () => {
    const files = new Set(pendingImages);
    for (const input of document.querySelectorAll('input[type="file"]')) {
      for (const file of input.files || []) if (file.type.startsWith("image/")) files.add(file);
    }
    return [...files];
  };
  const readImage = (file) => new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error || new Error("Could not read image"));
    reader.readAsDataURL(file);
  });
  const imageScans = new WeakMap();
  const scanImage = (file) => {
    if (!imageScans.has(file)) {
      imageScans.set(file, (async () => {
        const dataUrl = await readImage(file);
        const result = await new Promise((resolve, reject) => {
          chrome.runtime.sendMessage({ type: "ocr", dataUrl }, (response) => {
            if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
            else if (response?.error) reject(new Error(response.error));
            else if (typeof response?.text !== "string") reject(new Error("OCR returned no readable result"));
            else resolve(response);
          });
        });
        const text = result?.text || "";
        const findings = scanText(text);
        if (/aadhaar|income tax|passport|driving licen[cs]e|account no|cvv|password/i.test(text)) {
          findings.push({ name: "ID / banking document keywords", sev: "MEDIUM", count: 1, sample: "document-like image" });
        }
        return findings;
      })());
    }
    return imageScans.get(file);
  };
  const resumeSend = (event, trigger) => {
    checkingSend = false;
    bypass = true;
    if (event.type === "click") trigger.click();
    else if (event.type === "submit") {
      const form = event.target;
      if (form.requestSubmit) form.requestSubmit(event.submitter || undefined);
    } else {
      trigger.dispatchEvent(new KeyboardEvent("keydown", {
        key: "Enter", code: "Enter", keyCode: 13, which: 13, bubbles: true, cancelable: true
      }));
    }
    setTimeout(() => { bypass = false; }, 500);
  };
  async function guard(e, trigger) {
    if (!active || bypass) return;
    if (checkingSend) {
      e.preventDefault();
      e.stopImmediatePropagation();
      return;
    }
    const textFindings = scanText(textOf(composerOf(trigger)));
    const files = imageFiles();
    if (!textFindings.length && !files.length) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    checkingSend = true;
    try {
      const imageFindings = (await Promise.all(files.map(scanImage))).flat();
      const findings = [...textFindings, ...imageFindings];
      if (findings.length) {
        const neutralize = textFindings.length && !imageFindings.length
          ? () => {
            const composer = composerOf(trigger);
            if (!neutralizeComposer(composer)) {
              checkingSend = false;
              return;
            }
            for (const file of files) pendingImages.delete(file);
            resumeSend(e, trigger);
          }
          : undefined;
        showAlert({
          title: "Sensitive content mila - message roka gaya", findings,
          onNeutralize: neutralize,
          onProceed: () => {
            for (const file of files) pendingImages.delete(file);
            resumeSend(e, trigger);
          },
          onCancel: () => { checkingSend = false; }
        });
      } else {
        for (const file of files) pendingImages.delete(file);
        resumeSend(e, trigger);
      }
    } catch (error) {
      console.error("AI Shield could not scan an attached image:", error);
      showAlert({
        title: "Image scan nahi ho paya - message roka gaya",
        findings: [{ name: "OCR scan error", sev: "HIGH", count: 1, sample: "Image could not be checked" }],
        onProceed: () => resumeSend(e, trigger),
        onCancel: () => { checkingSend = false; }
      });
    }
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing && composerOf(e.target)) guard(e, e.target);
  }, true);
  document.addEventListener("click", (e) => {
    const b = e.target.closest?.("button,[role='button']");
    if (isSendBtn(b)) guard(e, b);
  }, true);
  document.addEventListener("submit", (e) => guard(e, e.target), true);

  // ---------- Paste (text + images) ----------
  document.addEventListener("paste", (e) => {
    if (!active) return;
    const pastedText = e.clipboardData?.getData("text") || "";
    const f = scanText(pastedText);
    if (f.length) {
      const composer = composerOf(e.target);
      showAlert({
        title: "Paste kiye text me sensitive data hai",
        findings: f,
        neutralizeLabel: "1-Click Neutralize",
        onNeutralize: () => neutralizeComposer(composer)
      });
    }
    for (const file of e.clipboardData?.files || []) if (file.type.startsWith("image/")) pendingImages.add(file);
  }, true);

  // OCR is completed before the send event is allowed through.
  document.addEventListener("change", (e) => {
    if (active && e.target.type === "file") {
      for (const file of e.target.files || []) if (file.type.startsWith("image/")) pendingImages.add(file);
    }
  }, true);
  document.addEventListener("drop", (e) => {
    if (active) for (const file of e.dataTransfer?.files || []) if (file.type.startsWith("image/")) pendingImages.add(file);
  }, true);
})();
