// Progressive enhancement only: every form works without this file.
document.documentElement.classList.add("js");

document.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-copy]");
  if (!b) return;
  e.preventDefault();
  const text = b.dataset.copy;
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const t = document.createElement("textarea");
    t.value = text; document.body.append(t); t.select(); document.execCommand("copy"); t.remove();
  }
  const old = b.textContent; b.textContent = "Copied ✓";
  setTimeout(() => (b.textContent = old), 1500);
});

document.addEventListener("submit", (e) => {
  const msg = e.target.dataset.confirm;
  if (msg && !confirm(msg)) e.preventDefault();
});

// Expiry picker: show the date box for "On a date…"; in auto forms a
// preset saves at once, a date saves when picked.
for (const box of document.querySelectorAll(".expiry")) {
  const sel = box.querySelector(".expiry-choice");
  const date = box.querySelector(".expiry-date");
  const auto = box.classList.contains("auto");
  sel.addEventListener("change", () => {
    date.hidden = sel.value !== "date";
    if (sel.value === "date") {
      date.required = true;
      if (!date.value) { date.focus(); date.showPicker?.(); return; }
    } else date.required = false;
    if (auto) box.closest("form").requestSubmit();
  });
  date.addEventListener("change", () => {
    if (auto && sel.value === "date" && date.value) box.closest("form").requestSubmit();
  });
}

// Uploads with a progress bar and drag and drop.
for (const form of document.querySelectorAll("form[data-upload]")) {
  const input = form.querySelector("input[type=file]");
  const prog = form.querySelector(".progress");
  const bar = form.querySelector(".bar");
  const ptext = form.querySelector(".ptext");
  const err = form.querySelector(".uperr");

  const send = (files) => {
    if (!files.length) return;
    const fd = new FormData();
    for (const f of files) fd.append("files", f, f.name);
    const xhr = new XMLHttpRequest();
    xhr.open("POST", form.action);
    xhr.setRequestHeader("Accept", "application/json");
    prog.hidden = false; err.hidden = true;
    const label = files.length === 1 ? files[0].name : `${files.length} files`;
    xhr.upload.onprogress = (ev) => {
      if (!ev.lengthComputable) return;
      const pct = Math.round((ev.loaded / ev.total) * 100);
      bar.style.width = pct + "%";
      ptext.textContent = `Uploading ${label}… ${pct}%`;
    };
    xhr.onload = () => {
      let body = {};
      try { body = JSON.parse(xhr.responseText); } catch {}
      if (xhr.status >= 200 && xhr.status < 300) {
        const n = Array.isArray(body.saved) ? body.saved.length : body.saved ?? files.length;
        const u = new URL(location.href);
        u.searchParams.set(location.pathname.startsWith("/admin") ? "msg" : "up",
          location.pathname.startsWith("/admin") ? `Uploaded ${n} file(s)` : n);
        location.replace(u);
      } else {
        prog.hidden = true;
        err.textContent = body.error || `Upload failed (${xhr.status}).`;
        err.hidden = false;
      }
    };
    xhr.onerror = () => {
      prog.hidden = true;
      err.textContent = "The connection dropped. Check your internet and try again.";
      err.hidden = false;
    };
    xhr.send(fd);
  };

  input.addEventListener("change", () => send([...input.files]));
  form.addEventListener("dragover", (e) => { e.preventDefault(); form.classList.add("over"); });
  form.addEventListener("dragleave", () => form.classList.remove("over"));
  form.addEventListener("drop", (e) => {
    e.preventDefault(); form.classList.remove("over");
    send([...e.dataTransfer.files].filter((f) => f.size > 0 || f.type));
  });
}
