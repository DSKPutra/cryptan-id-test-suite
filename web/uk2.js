/* Cryptan.ID Test Suite — dashboard UK-2 (membaca data/uk2/<set>/uk2_skenario.json). */
(() => {
  const SETS = [
    { id: "produk", label: "Produk", name: "Cryptan.ID SecureLib", sub: "Library · 3 tingkat · 33 objek" },
    { id: "ecdsa_p256_token", label: "Sampel materi 1", name: "ECDSA P-256 token", sub: "DS-K/S/I-01..06" },
    { id: "tls13_gateway", label: "Sampel materi 2", name: "TLS 1.3 gateway", sub: "PR-K/S/I-01..06" },
    { id: "hsm_x_sl3", label: "Sampel materi 3", name: "HSM-X SL 3", sub: "4 tingkat · ISO/IEC 19790" },
  ];
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const LAYER = { K: "Uji Kesesuaian", S: "Uji Keamanan", I: "Uji Implementasi" };
  const OUT = { "Memenuhi": "OK", "Memenuhi dengan Catatan": "RED", "Tidak Memenuhi": "TIDAK", "Inkonklusif": "muted" };
  const ST = { COCOK_VEKTOR_RESMI: "OK", KRITERIA: "muted", PERLU_VERIFIKASI: "RED", LULUS: "OK", TEMUAN: "TIDAK", "TIDAK BERLAKU": "muted", TERISI: "OK" };
  const b = (s, cls) => `<span class="b ${cls ?? ST[s] ?? OUT[s] ?? "muted"}">${esc(s)}</span>`;
  const table = (h, rows) => `<div class="tbl"><table><thead><tr>${h.map((x) => `<th>${esc(x)}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  const root = document.documentElement;
  try { const t = localStorage.getItem("cryptan-theme"); if (t) root.dataset.theme = t; } catch (e) {}
  $("#theme").onclick = () => {
    const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
    try { localStorage.setItem("cryptan-theme", root.dataset.theme); } catch (e) {}
  };
  const cache = {};
  let cur = null, tab = "verif", fLayer = "", fq = "";

  $("#sets").innerHTML = SETS.map((s) => `<button class="algo" data-s="${s.id}" aria-selected="false"><div class="prim">${esc(s.label)}</div>
    <div class="name">${esc(s.name)}</div><div class="row"><span class="b muted">${esc(s.sub)}</span></div></button>`).join("");
  $$("#sets .algo").forEach((x) => (x.onclick = () => show(x.dataset.s)));

  async function show(id) {
    cur = id;
    history.replaceState(null, "", "#" + id);
    $$("#sets .algo").forEach((x) => x.setAttribute("aria-selected", x.dataset.s === id));
    try {
      cache[id] ||= await (await fetch(`data/uk2/${id}/uk2_skenario.json`)).json();
    } catch (e) {
      $("#err").hidden = false; $("#err").textContent = "Gagal memuat data UK-2 — jalankan `make site`."; return;
    }
    render(cache[id]);
  }

  const TABS = [["verif", "Verifikasi (KUK 2.2)"], ["matrix", "Matriks skenario"], ["tc", "Test case"], ["param", "Ruang parameter"],
    ["review", "Telaah metode"], ["expected", "Expected value"], ["outcome", "Pemetaan hasil"], ["trace", "Keterlacakan"], ["kuk", "Peta KUK"]];

  function render(R) {
    const t = R.test_cases, e = R.expected.summary, v = R.verification;
    const base = `data/uk2/${cur}/`;
    $("#detail").innerHTML = `
      <div class="stats">
        <div class="stat"><div class="k">Verifikasi spesifikasi</div><div class="v">${esc(v.status)}</div><div class="s">${v.total_findings} temuan · 6 aturan</div></div>
        <div class="stat"><div class="k">Test case</div><div class="v">${t.length}</div><div class="s">K ${t.filter((x) => x.layer === "K").length} · S ${t.filter((x) => x.layer === "S").length} · I ${t.filter((x) => x.layer === "I").length}</div></div>
        <div class="stat"><div class="k">Skenario (sel)</div><div class="v">${R.scenarios.length}</div><div class="s">model ${R.profile.testing_model} tingkat</div></div>
        <div class="stat"><div class="k">Expected cocok vektor resmi</div><div class="v">${e.COCOK_VEKTOR_RESMI}</div><div class="s">${e.KRITERIA} kriteria · ${e.PERLU_VERIFIKASI} PERLU_VERIFIKASI</div></div>
        <div class="stat"><div class="k">Objek uji</div><div class="v">${R.profile.objects.length}</div><div class="s">${esc(R.profile.categories.join(", "))}</div></div>
      </div>
      ${R.inputs.notes.length ? `<p class="note">${R.inputs.notes.map(esc).join("<br>")}</p>` : ""}
      <div class="dl">
        <a href="${base}UK2_Dokumen_Skenario_Pengujian.md" download>⬇ Dokumen (.md)</a>
        <a href="${base}UK2_Dokumen_Skenario_Pengujian.docx" download>⬇ Dokumen (.docx)</a>
        <a href="${base}uk2_skenario.json" download>⬇ uk2_skenario.json (UK-3)</a>
        <a href="${base}test_cases.csv" download>⬇ test_cases.csv</a><a href="${base}test_cases.xlsx" download>⬇ .xlsx</a>
        <a href="${base}matriks_keterlacakan.csv" download>⬇ keterlacakan.csv</a><a href="${base}laporan_verifikasi.md" download>⬇ laporan_verifikasi.md</a>
      </div>
      <div class="tabs" role="tablist">${TABS.map(([k, l]) => `<button role="tab" data-t="${k}" aria-selected="${k === tab}">${l}</button>`).join("")}</div>
      <div id="pane"></div>
      <p class="note">Dibangkitkan ${esc(R.generated_at)} · masukan UK-1: ${esc(R.inputs.uk1)}</p>`;
    $$(".tabs button").forEach((x) => (x.onclick = () => { tab = x.dataset.t; render(R); }));
    $("#pane").innerHTML = P[tab](R);
    if (tab === "tc") bindTc(R);
  }

  const P = {
    verif: (R) => `<h2>Laporan verifikasi terhadap spesifikasi desain</h2>
      <div class="card">${table(["Aturan", "Deskripsi", "Diperiksa", "Status", "Temuan"], R.verification.rules.map((r) =>
        [`<b>(${r.rule})</b>`, esc(r.desc), r.checked, b(r.status), r.findings.map((f) => esc(f.detail)).join("<br>") || "—"]))}</div>
      ${R.verification.iso_coverage ? `<h3>Cakupan area ISO/IEC 19790</h3><div class="card">${table(["Area", ...R.profile.tiers],
        Object.entries(R.verification.iso_coverage).map(([a, v]) => [`<b>${a}</b>`, ...R.profile.tiers.map((t) => v[t].length ? v[t].map((x) => `<span class="chip">${esc(x)}</span>`).join("") : "—")]))}</div>` : ""}
      <h3>Resep tidak berlaku (aturan f)</h3><div class="card">${table(["Resep", "Alasan"], R.design.excluded.map((x) => [`<span class="mono">${esc(x.id)}</span>`, esc(x.reason)]))}</div>`,

    matrix: (R) => Object.entries(R.design.matrix).map(([g, m]) => `<h3>${esc(g)}</h3><div class="card">${table(["Tingkat", LAYER.K, LAYER.S, LAYER.I],
      Object.entries(m).map(([tier, cells]) => [`<b>${esc(tier)}</b>`, ..."KSI".split("").map((L) => {
        const sc = R.scenarios.find((s) => s.id === cells[L]);
        if (!sc) return "—";
        return `<div class="note">${esc(sc.template_cell).slice(0, 140)}</div>` + (sc.recipes.map((x) => `<span class="chip">${esc(x)}</span>`).join("") || b("TIDAK BERLAKU"))
          + (sc.filled_from_template ? ` <span class="tag claim">templat</span>` : "");
      })]))}</div>`).join("") + `<p class="note">Rantai lintas-algoritma: ${esc(R.design.cross.chain.join(" → "))}</p>`,

    tc: (R) => `<div class="row3" style="margin-top:14px"><label class="fld">Cari <input id="tq" type="search" value="${esc(fq)}" placeholder="ID, judul, target"></label>
      <label class="fld">Lapis <select id="tl"><option value="">Semua</option>${"KSI".split("").map((L) => `<option value="${L}" ${fLayer === L ? "selected" : ""}>${LAYER[L]}</option>`).join("")}</select></label></div>
      <div class="card" id="tclist"></div>`,

    param: (R) => Object.entries(R.param_space.categories).map(([c, v]) => `<h3>${esc(c)} <span class="note">pairwise ${v.pairwise.full_combinations.toLocaleString("id-ID")} → ${v.pairwise.pairwise_combinations} kombinasi</span></h3>
      <div class="card">${table(["ID", "Parameter", "Kelas", "Status", "Nilai uji"], v.params.map((p) => [`<span class="mono">${esc(p.id)}</span>`, esc(p.name), esc(p.class), esc(p.status),
        p.values.map((x) => `<span class="chip ${x.in_spec ? "" : "off"}" title="${esc(x.technique)}">${esc(x.value)}</span>`).join("")]))}</div>`).join(""),

    review: (R) => `<div class="card">${table(["Metode", "Sel", "N1", "N2", "N3", "N4", "Putusan"], R.method_review.methods.map((m) => [`<b>${esc(m.method_id)}</b> ${esc(m.name)}`,
      `${esc(m.tier)} × ${m.layer}`, ...Object.values(m.needs).map((x) => (x ? "✔" : "✘")), m.relevant ? b("RELEVAN", "OK") : b(m.verdict, "TIDAK")]))}</div>
      <p class="note">N1 jenis algoritma · N2 desain & teknik implementasi · N3 tren serangan · N4 best practice. Sel kosong: ${R.method_review.empty_cells.length} (diisi templat materi).</p>`,

    expected: (R) => `<div class="card">${table(["Berkas", "Target", "Jenis", "Status", "Cocok/total", "SHA-256"],
      R.expected.manifest.filter((m) => m.status !== "KRITERIA").sort((a, c) => a.status.localeCompare(c.status)).map((m) => [`<span class="mono">${esc(m.id)}</span>`, esc(m.target), esc(m.kind), b(m.status),
        m.summary ? `${m.summary.matched}/${m.summary.total}` : "—", `<span class="mono">${esc(m.sha256.slice(0, 16))}…</span>`]))}</div>
      <p class="note">${R.expected.summary.KRITERIA} berkas expected berjenis kriteria (statistik/kriptanalitik/implementasi/negatif) tidak ditampilkan; lihat MANIFEST.json.</p>`,

    outcome: (R) => `<div class="card">${table(["Kondisi temuan", "Parameter pemicu", "Kemungkinan hasil", "Tindak lanjut", "Sumber"],
      R.outcome_map.map((o) => [esc(o.condition), esc(o.trigger), b(o.outcome, OUT[o.outcome]), esc(o.action), `<span class="note">${esc(o.source)}</span>`]))}</div>`,

    trace: (R) => `<div class="card">${table(["Kebutuhan", "Uraian", "Metode", "Skenario", "Test case", "Area"], R.traceability.slice(0, 300).map((r) =>
      [`<span class="mono">${esc(r.requirement_id)}</span>`, esc(r.requirement), esc(r.method), `<span class="mono">${esc(r.scenario)}</span>`, `<b>${esc(r.test_case)}</b>`, esc(r.area)]))}</div>`,

    kuk: () => table(["KUK", "Deskripsi", "Bab", "File"], [["1.1", "Metode ditelaah", "2", "method_review.py"], ["1.2", "Parameter ditelaah", "1, 2", "param_space.py"],
      ["2.1", "Skenario didesain", "3", "designer.py, data/recipes.yaml"], ["2.2", "Verifikasi terhadap spesifikasi desain (aspek kritis)", "4", "verifier.py"],
      ["2.3", "Identifikasi test case", "5", "testcase.py, schema/"], ["2.4", "Expected value", "6", "expected.py, data/vectors/"], ["2.5", "Kompilasi", "7, 8", "compiler.py"]].map((r) => r.map(esc))),
  };

  function bindTc(R) {
    const draw = () => {
      const q = fq.toLowerCase();
      const rows = R.test_cases.filter((t) => (!fLayer || t.layer === fLayer) && (!q || (t.id + t.title + t.targets.join(" ")).toLowerCase().includes(q)));
      $("#tclist").innerHTML = rows.map((t) => `<details class="comp"><summary><span class="id">${esc(t.id)}</span><span class="nm">${esc(t.title)}</span>
        ${t.area ? `<span class="b muted">${esc(t.area)}</span>` : ""}<span class="b muted">${esc(t.tier)}</span>${t.negative ? b("negatif", "RED") : ""}${b(t.expected_status[0])}</summary>
        <div class="body"><p class="role">${esc(t.narrative)}</p>
        ${t.material_reference ? `<p class="note"><b>Materi:</b> ${esc(t.material_reference.params)} — ${esc(t.material_reference.procedure)}</p>` : ""}
        ${table(["Field", "Isi"], [["Target", esc(t.targets.join(", "))], ["Prasyarat", t.prerequisites.map(esc).join("<br>")], ["Langkah", t.steps.map(esc).join("<br>")],
          ["Kriteria lulus", esc(t.pass)], ["Parameter", t.parameters.slice(0, 40).map((p) => `<span class="chip ${p.in_spec ? "" : "off"}">${esc(p.name)}=${esc(p.value)}</span>`).join("") || "—"],
          ["Metode UK-1", esc(t.methods.join(", "))], ["Standar", esc(t.standard_labels.join(", "))], ["Prioritas / pelaksana", esc(`${t.priority} · ${t.executor}`)],
          ["Runner UK-3", `<code>${esc(t.runner.action)}</code> — ${esc(t.runner.description)}`], ["Expected", t.expected.map((x) => `${b(x.status)} <span class="mono">${esc(x.file)}</span>`).join("<br>") || "kriteria"]])}
        </div></details>`).join("") || `<p class="note" style="padding:12px">Tidak ada test case.</p>`;
    };
    $("#tq").oninput = (ev) => { fq = ev.target.value; draw(); };
    $("#tl").onchange = (ev) => { fLayer = ev.target.value; draw(); };
    draw();
  }

  const h = location.hash.slice(1);
  show(SETS.some((s) => s.id === h) ? h : "produk");
})();
