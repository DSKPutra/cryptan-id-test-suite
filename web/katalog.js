/* Cryptan.ID Test Suite — Katalog Algoritma Uji (dropdown JS + deteksi Python via Pyodide). */
(() => {
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const PYODIDE = "https://cdn.jsdelivr.net/pyodide/v0.27.2/full/pyodide.js";
  const IR8547 = "NIST IR 8547 (ipd): algoritma kuantum-rentan 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205";
  const STORE = "cryptan-katalog-sel";

  // ---- tema
  const root = document.documentElement;
  try { const t = localStorage.getItem("cryptan-theme"); if (t) root.dataset.theme = t; } catch (e) {}
  $("#theme").onclick = () => {
    const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
    try { localStorage.setItem("cryptan-theme", root.dataset.theme); } catch (e) {}
  };

  // ---- model katalog (padanan algo_catalog/schema.py)
  let CAT = null, ENT = {}, PRIM = {};
  const perKey = (v, k) => (v && typeof v === "object" && !Array.isArray(v)) ? (v[k] ?? v[String(k)] ?? "PERLU_VERIFIKASI") : (v === "key" ? k : v);
  const keys = (e) => (e.key_bits && e.key_bits.length ? e.key_bits : [null]);
  const comboId = (e, k) => {
    const tpl = e.combo_id || (e.key_bits && e.key_bits.length ? `${e.family}-{k}-${e.variant}` : e.id);
    return k === null ? tpl.replace("-{k}", "").replace("{k}", "") : tpl.replace("{k}", String(k));
  };
  const row = (e, k) => ({
    id: comboId(e, k), entry_id: e.id, primitive: e.primitive, family: e.family, variant: e.variant, key_bits: k,
    security_strength_bits: perKey(e.security_strength_bits, k), security_category: perKey(e.security_category, k),
    status_nist: perKey(e.status_nist, k), standards: e.standards || [], quantum_vulnerable: !!e.quantum_vulnerable,
  });
  const strengthLt = (s) => (typeof s === "number" ? s < 112 : typeof s === "string" && /^<\d+$/.test(s) && +s.slice(1) <= 112);
  function warnings(r) {
    const w = [], bad = { deprecated: "deprecated", legacy_use: "hanya legacy use", disallowed: "disallowed" };
    if (bad[r.status_nist]) w.push({ level: "TINGGI", message: `${r.id}: status NIST ${bad[r.status_nist]} (SP 800-131A Rev.2)` });
    if (strengthLt(r.security_strength_bits)) w.push({ level: "TINGGI", message: `${r.id}: security strength ${r.security_strength_bits} bit < 112 bit (SP 800-57 Pt.1)` });
    if (r.quantum_vulnerable) w.push({ level: "SEDANG", message: `${r.id}: rentan kuantum — ${IR8547}` });
    if ([r.status_nist, r.security_strength_bits].map(String).includes("PERLU_VERIFIKASI")) w.push({ level: "INFO", message: `${r.id}: status/strength PERLU_VERIFIKASI` });
    return w;
  }

  // ---- seleksi (state per-penampil di localStorage — kenyamanan saja)
  let SEL = {};
  try { SEL = JSON.parse(localStorage.getItem(STORE) || "{}"); } catch (e) { SEL = {}; }
  const save = () => { try { localStorage.setItem(STORE, JSON.stringify(SEL)); } catch (e) {} };
  function add(e, k, inp) {
    const r = row(e, k);
    const it = SEL[r.id] || (SEL[r.id] = { ...r, inputs: [], confidence: 0 });
    if (!it.inputs.some((x) => x.type === inp.type && x.ref === inp.ref)) it.inputs.push(inp);
    it.confidence = Math.max(it.confidence, inp.confidence ?? 1);
    return r.id;
  }

  // ---- dropdown
  const tree = () => {
    const t = {};
    for (const e of CAT.entries) ((t[e.primitive] ||= {})[e.family] ||= []).push(e);
    return t;
  };
  let T = {};
  const match = (e, q) => !q || [e.family, e.variant, e.id, ...keys(e).map((k) => comboId(e, k))].some((s) => s.toLowerCase().includes(q));
  function renderPrim() {
    const q = $("#q").value.trim().toLowerCase();
    const prims = Object.keys(PRIM).filter((p) => T[p] && Object.values(T[p]).some((es) => es.some((e) => match(e, q))));
    const cur = $("#prim").value;
    $("#prim").innerHTML = prims.map((p) => `<option value="${p}">${esc(PRIM[p])}</option>`).join("");
    if (prims.includes(cur)) $("#prim").value = cur;
    renderFam();
  }
  function renderFam() {
    const q = $("#q").value.trim().toLowerCase(), p = $("#prim").value;
    const fams = Object.keys(T[p] || {}).sort().filter((f) => T[p][f].some((e) => match(e, q)));
    const cur = $("#fam").value;
    $("#fam").innerHTML = fams.map((f) => `<option>${esc(f)}</option>`).join("");
    if (fams.includes(cur)) $("#fam").value = cur;
    renderVariants();
  }
  function renderVariants() {
    const q = $("#q").value.trim().toLowerCase();
    const es = (T[$("#prim").value] || {})[$("#fam").value] || [];
    $("#variants").innerHTML = es.filter((e) => match(e, q) || !q).map((e) =>
      `<label><input type="checkbox" value="${esc(e.id)}"> ${esc(e.variant)}</label>`).join("") || `<span class="note">—</span>`;
    $$("#variants input").forEach((c) => (c.onchange = renderCombos));
    renderCombos();
  }
  function renderCombos() {
    const ids = $$("#variants input:checked").map((c) => c.value);
    const html = [];
    for (const id of ids) {
      const e = ENT[id];
      for (const k of keys(e)) {
        const r = row(e, k);
        html.push(`<label title="${esc(r.status_nist)} · ${esc(r.security_strength_bits)} bit"><input type="checkbox" data-e="${esc(id)}" data-k="${k ?? ""}" checked>
          ${esc(r.id)} <span class="st">${esc(r.status_nist)}</span></label>`);
      }
    }
    $("#combos").innerHTML = html.join("") || `<span class="note">Pilih varian terlebih dahulu</span>`;
  }
  $("#q").oninput = renderPrim;
  $("#prim").onchange = renderFam;
  $("#fam").onchange = renderVariants;
  $("#allv").onclick = () => { $$("#variants input").forEach((c) => (c.checked = true)); renderCombos(); };
  $("#allk").onclick = () => $$("#combos input").forEach((c) => (c.checked = true));
  $("#addpick").onclick = () => {
    const picked = $$("#combos input:checked");
    picked.forEach((c) => add(ENT[c.dataset.e], c.dataset.k === "" ? null : +c.dataset.k,
      { type: "dropdown", ref: `${$("#fam").value}: ${ENT[c.dataset.e].variant}`, confidence: 1, evidence: "dipilih dari katalog" }));
    save(); renderSel();
  };

  // ---- tab
  $$(".tabs button").forEach((b) => (b.onclick = () => {
    $$(".tabs button").forEach((x) => x.setAttribute("aria-selected", x === b));
    ["drop", "file", "link", "product"].forEach((t) => ($(`#p-${t}`).hidden = t !== b.dataset.t));
  }));

  // ---- deteksi via Pyodide (algo_catalog/normalize.py yang sama dengan CLI)
  let py = null;
  async function pyReady() {
    if (py) return py;
    $("#pystat").textContent = "Memuat Python (Pyodide)…";
    await new Promise((res, rej) => { const s = document.createElement("script"); s.src = PYODIDE; s.onload = res; s.onerror = rej; document.head.appendChild(s); });
    const pyo = await loadPyodide();
    pyo.FS.mkdirTree("/home/pyodide/algo_catalog");
    pyo.FS.writeFile("/home/pyodide/algo_catalog/__init__.py", "");
    for (const f of ["schema.py", "normalize.py"]) pyo.FS.writeFile(`/home/pyodide/algo_catalog/${f}`, await (await fetch(`py/algo_catalog/${f}`)).text());
    pyo.globals.set("CAT_JSON", JSON.stringify(CAT.entries));
    await pyo.runPythonAsync(`
import json, sys
sys.path.insert(0, "/home/pyodide")
from algo_catalog.schema import Entry
from algo_catalog.normalize import Matcher, best
_M = Matcher([Entry.from_dict(d) for d in json.loads(CAT_JSON)])
def detect(text, kb):
    return json.dumps(best(_M.find(text, key_bits=int(kb) if kb else None)))
`);
    $("#pystat").textContent = "Python siap.";
    return (py = pyo);
  }
  let CANDS = [];
  async function detectText(text, type, ref) {
    const pyo = await pyReady();
    const out = JSON.parse(pyo.globals.get("detect")(text, $("#kb").value || null));
    out.forEach((d) => CANDS.push({ ...d, type, ref }));
    renderCands();
    return out.length;
  }
  $("#detect").onclick = async () => {
    const btn = $("#detect"); btn.disabled = true;
    try {
      let n = 0;
      for (const f of $("#files").files) n += await detectText(await f.text(), "file", f.name);
      if ($("#paste").value.trim()) n += await detectText($("#paste").value, "file", "teks tempel");
      $("#pystat").textContent = `${n} deteksi — konfirmasi di bawah.`;
    } catch (e) { $("#pystat").textContent = "Gagal: " + e; }
    btn.disabled = false;
  };
  $("#fetch").onclick = async () => {
    const u = $("#url").value.trim(); if (!u) return;
    $("#linkstat").textContent = "Mengunduh…";
    try {
      const r = await fetch(u); const ct = r.headers.get("content-type") || "";
      if (ct.includes("pdf")) throw new Error("PDF — gunakan CLI (python -m algo_catalog select --url …)");
      const html = await r.text();
      const text = new DOMParser().parseFromString(html, "text/html").body?.innerText || html;
      const n = await detectText(text, "link", u);
      $("#linkstat").textContent = `${n} deteksi.`;
    } catch (e) { $("#linkstat").textContent = `Tidak dapat dibaca dari browser (${e.message || e}). Gunakan CLI.`; }
  };
  function renderCands() {
    $("#cands").hidden = !CANDS.length;
    const minc = +$("#minc").value || 0.6;
    $("#candtbl").innerHTML = `<thead><tr><th></th><th>ID kanonik</th><th>Keyakinan</th><th>Kunci dari</th><th>Sumber</th><th>Bukti</th></tr></thead><tbody>` +
      CANDS.map((d, i) => `<tr><td><input type="checkbox" data-i="${i}" ${d.confidence >= minc ? "checked" : ""}></td><td><b class="mono">${esc(d.id)}</b></td>
        <td class="num">${d.confidence.toFixed(2)}</td><td>${esc(d.key_from)}</td><td>${esc(d.type)}: ${esc(d.ref)}${d.line ? ":" + d.line : ""}</td>
        <td class="ev">${esc(d.evidence)}</td></tr>`).join("") + "</tbody>";
  }
  $("#confirm").onclick = () => {
    $$("#candtbl input:checked").forEach((c) => {
      const d = CANDS[+c.dataset.i], e = ENT[d.entry_id];
      add(e, d.key_bits, { type: d.type, ref: d.ref, confidence: d.confidence, evidence: d.evidence, match: d.match, line: d.line });
    });
    CANDS = []; renderCands(); save(); renderSel();
  };
  $("#discard").onclick = () => { CANDS = []; renderCands(); };

  // ---- daftar terpilih
  function renderSel() {
    const order = Object.keys(PRIM);
    const rows = Object.values(SEL).sort((a, b) => order.indexOf(a.primitive) - order.indexOf(b.primitive) || a.id.localeCompare(b.id));
    $("#count").textContent = rows.length;
    $("#seltbl").innerHTML = rows.length ? `<thead><tr><th>ID</th><th>Strength</th><th>Status</th><th>Sumber</th><th></th></tr></thead><tbody>` +
      rows.map((r) => {
        const e = ENT[r.entry_id];
        const ks = (e?.key_bits || []).length > 1 ? `<select data-ch="${esc(r.id)}">${e.key_bits.map((k) => `<option ${k === r.key_bits ? "selected" : ""}>${k}</option>`).join("")}</select>` : "";
        const st = r.status_nist === "acceptable" ? "OK" : ["disallowed", "deprecated", "legacy_use"].includes(r.status_nist) ? "TIDAK" : "RED";
        return `<tr><td><b class="mono">${esc(r.id)}</b><div class="note">${esc(PRIM[r.primitive])}</div></td>
          <td class="num">${esc(r.security_strength_bits)}${r.security_category ? ` <span class="note">(kat. ${esc(r.security_category)})</span>` : ""}</td>
          <td><span class="b ${st}">${esc(r.status_nist)}</span></td><td>${esc([...new Set(r.inputs.map((i) => i.type))].join(", "))}</td>
          <td>${ks}<button class="x" data-rm="${esc(r.id)}" title="hapus">✕</button></td></tr>`;
      }).join("") + "</tbody>" : `<tbody><tr><td class="note">Belum ada algoritma. Gunakan Dropdown, File, atau Link.</td></tr></tbody>`;
    $$("[data-rm]").forEach((b) => (b.onclick = () => { delete SEL[b.dataset.rm]; save(); renderSel(); }));
    $$("[data-ch]").forEach((s) => (s.onchange = () => {
      const old = SEL[s.dataset.ch]; delete SEL[s.dataset.ch];
      const nid = add(ENT[old.entry_id], +s.value, { type: "edit", ref: `ubah dari ${old.id}`, confidence: 1, evidence: "suntingan pengguna" });
      SEL[nid].inputs = old.inputs.concat(SEL[nid].inputs); save(); renderSel();
    }));
    const by = {};
    rows.forEach((r) => (by[PRIM[r.primitive]] = (by[PRIM[r.primitive]] || 0) + 1));
    $("#summary").textContent = rows.length ? `${rows.length} kombinasi · ` + Object.entries(by).map(([p, n]) => `${p} ${n}`).join(" · ") : "";
    const ws = rows.flatMap(warnings).filter((w) => w.level !== "INFO");
    $("#warns").innerHTML = ws.length ? `<h3>⚠ Peringatan (${ws.length})</h3>` + ws.map((w) => `<div class="warn ${w.level}">${esc(w.message)}</div>`).join("") : "";
  }
  const COLS = ["No", "Primitif", "Algoritma", "Varian", "Panjang kunci", "Security strength", "Status NIST", "Standar", "Sumber input", "Bukti", "ID kanonik"];
  const list = () => Object.values(SEL);
  const dl = (name, mime, text) => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([text], { type: mime })); a.download = name; a.click(); };
  $("#dlcsv").onclick = (ev) => {
    ev.preventDefault();
    const q = (s) => `"${String(s ?? "").replace(/"/g, '""')}"`;
    const lines = [COLS.map(q).join(",")].concat(list().map((r, i) => [i + 1, PRIM[r.primitive], r.family, r.variant, r.key_bits ?? "—",
      r.security_strength_bits, r.status_nist, r.standards.join(", "), [...new Set(r.inputs.map((x) => x.type))].join(", "),
      r.inputs[0]?.evidence || "", r.id].map(q).join(",")));
    dl("Daftar_Algoritma_Uji.csv", "text/csv", lines.join("\n"));
  };
  const doc = () => ({ schema: "cryptan.algo_catalog.algorithms_under_test.v1", generated_at: new Date().toISOString(), source: "web/katalog.html",
    summary: { total_combinations: list().length }, warnings: list().flatMap(warnings), items: list() });
  $("#dljson").onclick = (ev) => { ev.preventDefault(); dl("algorithms_under_test.json", "application/json", JSON.stringify(doc(), null, 2)); };
  $("#dlyaml").onclick = (ev) => { ev.preventDefault(); dl("algorithms_under_test.yaml", "text/yaml", "# JSON adalah subset YAML yang sah\n" + JSON.stringify(doc(), null, 2)); };
  $("#clear").onclick = (ev) => { ev.preventDefault(); if (confirm("Kosongkan daftar terpilih?")) { SEL = {}; save(); renderSel(); } };

  // ---- daftar produk (keluaran CLI)
  let PROD = null;
  function renderProduct() {
    if (!PROD) { $("#product").innerHTML = `<p class="note">Belum ada keluaran algo_catalog.</p>`; return; }
    const s = PROD.summary;
    $("#product").innerHTML = `<p><b>${s.total_combinations}</b> kombinasi · ${Object.entries(s.by_primitive).map(([p, n]) => `${esc(PRIM[p])} ${n}`).join(" · ")}
      · ${PROD.warnings.filter((w) => w.level === "TINGGI").length} peringatan tinggi · dibangkitkan ${esc(PROD.generated_at)}</p>
      <div class="card"><div class="tbl"><table><thead><tr><th>ID</th><th>Strength</th><th>Status</th><th>Profil UK-1</th></tr></thead><tbody>
      ${PROD.items.map((i) => `<tr><td class="mono">${esc(i.id)}</td><td>${esc(i.security_strength_bits)}</td><td>${esc(i.status_nist)}</td>
        <td>${i.uk1_profile ? `<span class="b OK">${esc(i.uk1_profile.split("/").pop())}</span>` : "—"}</td></tr>`).join("")}</tbody></table></div></div>`;
  }
  $("#loadprod").onclick = () => {
    if (!PROD) return;
    for (const i of PROD.items) {
      const e = ENT[i.entry_id]; if (!e) continue;
      add(e, i.key_bits ?? null, { type: i.inputs?.[0]?.type || "file", ref: "algorithms_under_test.yaml", confidence: i.confidence ?? 1, evidence: i.inputs?.[0]?.evidence || "" });
    }
    save(); renderSel();
  };

  // ---- muat
  (async () => {
    try {
      CAT = await (await fetch("data/catalog.json")).json();
      PRIM = CAT.primitives;
      CAT.entries.forEach((e) => (ENT[e.id] = e));
      T = tree();
      $("#catinfo").textContent = `Katalog: ${CAT.entries.length} entri · ${CAT.counts.total} kombinasi (seed + hasil scraping NIST).`;
      renderPrim(); renderSel();
      try { PROD = await (await fetch("data/algo_catalog/algorithms_under_test.json")).json(); } catch (e) { PROD = null; }
      renderProduct();
    } catch (e) {
      $("#catinfo").textContent = "Gagal memuat data/catalog.json — jalankan `make site`.";
    }
  })();
})();
