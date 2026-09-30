/* Cryptan.ID Test Suite — dashboard statis UK-1 (membaca data/uk1/*.json). */
(() => {
  const MODULES = [
    { id: "UK-1", title: "Menentukan Metode Pengujian", ready: true },
    { id: "UK-2", title: "Menyusun Skenario Pengujian" }, { id: "UK-3" }, { id: "UK-4" },
    { id: "UK-5" }, { id: "UK-6" }, { id: "UK-7" }, { id: "UK-8" },
  ];
  const $ = (s, el = document) => el.querySelector(s);
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmt = (v) => {
    if (v === null || v === undefined) return "—";
    if (typeof v === "number") return Number.isInteger(v) ? String(v) : v.toPrecision(4).replace(/\.?0+$/, "");
    if (Array.isArray(v)) return v.map(fmt).join(", ");
    if (typeof v === "object") return Object.entries(v).map(([k, x]) => `${k}=${fmt(x)}`).join("; ");
    return String(v);
  };
  const badge = (s) => {
    const cls = s === "LAYAK VERSI TEREDUKSI" ? "RED" : s === "TIDAK LAYAK" ? "TIDAK" : s;
    return `<span class="b ${esc(cls)}">${esc(s.replace("_", " "))}</span>`;
  };
  const src = (s) => `<span class="tag ${s.includes("LANGSUNG") ? "direct" : s.includes("LITERATUR") ? "lit" : "claim"}">${esc(s)}</span>`;
  const table = (heads, rows) => `<div class="tbl"><table><thead><tr>${heads.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead>
    <tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;

  // ---- tema
  const root = document.documentElement;
  try { const t = localStorage.getItem("cryptan-theme"); if (t) root.dataset.theme = t; } catch (e) {}
  $("#theme").onclick = () => {
    const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
    try { localStorage.setItem("cryptan-theme", root.dataset.theme); } catch (e) {}
  };

  $("#modules").innerHTML = MODULES.map((m) => m.ready
    ? `<a href="#" title="${esc(m.title)}">${m.id}</a>`
    : `<span title="${esc(m.title || "segera")} — segera">${m.id}</span>`).join("");

  const cache = {};
  let index = null, current = null, tab = "komponen";

  async function load() {
    try {
      index = await (await fetch("data/uk1/index.json")).json();
    } catch (e) {
      $("#err").hidden = false;
      $("#err").textContent = "Gagal memuat data/uk1/index.json — jalankan `make site` terlebih dahulu.";
      return;
    }
    if (index.repo) $("#repo-link").href = index.repo;
    $("#algos").innerHTML = index.algorithms.map((a) => `
      <button class="algo" role="tab" data-slug="${esc(a.slug)}" aria-selected="false">
        <div class="prim">${esc(a.primitive_label)}</div>
        <div class="name">${esc(a.id)}</div>
        <div class="row">${badge(a.kat.endsWith("LULUS") ? "LULUS" : "GAGAL")}
          <span class="b muted">${a.selected.length} metode</span>
          ${a.weak.length ? `<span class="b BERPOTENSI_LEMAH">${a.weak.length} lemah</span>` : ""}</div>
      </button>`).join("");
    document.querySelectorAll(".algo").forEach((b) => (b.onclick = () => show(b.dataset.slug)));
    const h = location.hash.slice(1);
    show(index.algorithms.some((a) => a.slug === h) ? h : index.algorithms[0].slug);
  }

  async function show(slug) {
    current = slug;
    history.replaceState(null, "", "#" + slug);
    document.querySelectorAll(".algo").forEach((b) => b.setAttribute("aria-selected", b.dataset.slug === slug));
    if (!cache[slug]) cache[slug] = await (await fetch(`data/uk1/${slug}/uk1_penetapan_metode.json`)).json();
    render(cache[slug], index.algorithms.find((a) => a.slug === slug));
  }

  const TABS = [
    ["komponen", "Telaah komponen"], ["matriks", "Matriks metode"], ["sumberdaya", "Sumber daya"],
    ["metode", "Metode & parameter"], ["jejak", "Keterlacakan"], ["serangan", "Tren serangan"],
    ["standar", "Standar"], ["profil", "Profil produk"], ["kuk", "Peta KUK"],
  ];

  function render(r, meta) {
    const sel = r.selection, alg = r.profile.algorithm;
    const files = meta.files;
    $("#detail").innerHTML = `
      <div class="stats">
        <div class="stat"><div class="k">KAT implementasi referensi</div><div class="v">${r.kat.passed}/${r.kat.total}</div><div class="s">${badge(r.kat.status)}</div></div>
        <div class="stat"><div class="k">Komponen ditelaah</div><div class="v">${r.component_summary.total}</div>
          <div class="s">${r.component_summary.berpotensi_lemah.length} berpotensi lemah · ${r.component_summary.perhatian.length} perhatian</div></div>
        <div class="stat"><div class="k">Metode terpilih</div><div class="v">${sel.selected.length}</div><div class="s">${sel.rejected.length} ditolak</div></div>
        <div class="stat"><div class="k">Upaya uji</div><div class="v">${sel.effort_hours_total} j</div><div class="s">dari ${sel.person_hours_available} jam-orang · ${esc(sel.effort_fit)}</div></div>
        <div class="stat"><div class="k">Akses penguji</div><div class="v" style="font-size:18px">${esc(r.profile.tester.access.replace("_", " "))}</div><div class="s">${esc(alg.structure)}</div></div>
      </div>
      <div class="dl">
        <a href="data/uk1/${files.md}" download>⬇ Dokumen (.md)</a>
        ${files.docx ? `<a href="data/uk1/${files.docx}" download>⬇ Dokumen (.docx)</a>` : ""}
        <a href="data/uk1/${files.json}" download>⬇ JSON (masukan UK-2)</a>
        <a href="data/uk1/${files.csv_map}" download>⬇ matriks_pemetaan.csv</a>
        <a href="data/uk1/${files.csv_trace}" download>⬇ matriks_keterlacakan.csv</a>
      </div>
      <div class="tabs" role="tablist">${TABS.map(([k, t]) => `<button role="tab" data-tab="${k}" aria-selected="${k === tab}">${t}</button>`).join("")}</div>
      <div id="pane"></div>
      <p class="note">Dibangkitkan ${esc(r.generated_at)} · mode ${esc(r.mode)} · ${esc(r.app.name)} v${esc(r.app.version)} · data produk ilustratif.</p>`;
    document.querySelectorAll(".tabs button").forEach((b) => (b.onclick = () => { tab = b.dataset.tab; render(r, meta); }));
    $("#pane").innerHTML = PANES[tab](r);
  }

  const PANES = {
    komponen: (r) => `<h2>Hasil telaah komponen (KUK 2.1)</h2><div class="card">${r.components.map((c) => `
      <details class="comp" ${c.status !== "OK" ? "open" : ""}>
        <summary><span class="id">${esc(c.id)}</span><span class="nm">${esc(c.name)}</span>${badge(c.status)}</summary>
        <div class="body"><p class="role">${esc(c.role)} · tag: ${c.tags.map((t) => `<code>${esc(t)}</code>`).join(" ")}</p>
        ${table(["Pemeriksaan", "Nilai", "Acuan", "Status", "Sumber", "Catatan"], c.findings.map((f) =>
          [esc(f.check), `<span class="mono">${esc(fmt(f.value))}</span>`, esc(f.reference), badge(f.status), src(f.source), esc(f.note)]))}</div>
      </details>`).join("")}</div>`,

    matriks: (r) => {
      const levels = ["Unit", "Integrasi", "Sistem"];
      const selected = new Set(r.selection.selected.map((s) => s.method_id));
      const chips = (ids) => ids.map((m) => `<span class="chip ${selected.has(m) ? "" : "off"}">${esc(m)}</span>`).join("") || "—";
      return `<h2>Matriks komponen–kelemahan–metode (KUK 2.2)</h2>
        <p class="note">Tiga lapis pengujian × level uji. Chip dicoret = metode dipetakan tetapi tidak terpilih.</p>
        <div class="grid3"><div class="hd lh">Lapis \\ Level</div>${levels.map((l) => `<div class="hd lh">${l}</div>`).join("")}
        ${Object.entries(r.layer_summary).map(([layer, v]) => `<div class="hd">${esc(layer)}</div>${levels.map((l) => `<div data-l="${l}">${chips(v[l])}</div>`).join("")}`).join("")}</div>
        <h3>Rincian (${r.matrix.length} baris)</h3><div class="card">${table(["Komponen", "Status", "Kelemahan", "Serangan", "Metode", "Lapis / level", "Standar", "Akses"],
          r.matrix.map((m) => [`<b>${esc(m.component_id)}</b> ${esc(m.component)}`, badge(m.component_status), esc(m.weakness),
            `<span class="mono">${esc(m.attacks.join(", ") || "—")}</span>`, `<b>${esc(m.method_id)}</b> ${esc(m.method)}`,
            `${esc(m.layer)} / ${esc(m.level)}`, esc(m.standards.join(", ")), m.access_ok ? `✔ ${esc(m.access_required)}` : `<span class="b TIDAK">✘ ${esc(m.access_required)}</span>`]))}</div>`;
    },

    sumberdaya: (r) => {
      const b = r.resources.benchmark, c = r.resources.capacity;
      return `<h2>Estimasi sumber daya & kelayakan (KUK 2.3)</h2>
        <h3>Benchmark mesin lab ${src("HASIL UJI LANGSUNG")}</h3>
        <div class="card">${table(["Operasi", "ops/detik"], Object.entries(b.ops_per_sec).map(([k, v]) => [esc(k), `<span class="num">${v.toLocaleString("id-ID")}</span>`]))}</div>
        <p class="note">${esc(b.machine.system)} · ${esc(b.machine.logical_cpus)} CPU logis · Python ${esc(b.machine.python)} · ${esc(b.implementation)}</p>
        <h3>Sumber daya internal</h3>
        <div class="card">${table(["Sumber daya", "Nilai"], [
          ["SDM", esc(c.personnel.map((p) => `${p.count}× ${p.role}`).join("; "))],
          ["Jadwal", `${c.schedule_days} hari × ${c.hours_per_day} jam = ${c.person_hours} jam-orang`],
          ["Komputasi", `${c.compute.machines} mesin × ${c.compute.cores} core · ${c.compute.ram_gb} GB`],
          ["Anggaran per metode", `${c.method_budget_hours} jam`], ["Tools", esc(c.tools_available.join(", "))]])}</div>
        <h3>Estimasi per metode <span class="note">waktu = 2^k ÷ (ops/detik × core × speedup)</span></h3>
        <div class="card">${table(["Metode", "k", "Estimasi penuh", "Varian tereduksi", "Data / memori", "Status", "Alasan"],
          r.resources.estimates.map((e) => [`<b>${esc(e.method_id)}</b>`, `<span class="num">${esc(e.ops_log2)}</span>`, esc(e.time_human),
            e.reduced ? `${esc(e.reduced.desc)} — <b>${esc(e.reduced.time_human)}</b>` : "—", `${esc(e.data)} / ${esc(e.memory)}`, badge(e.status), esc(e.reason)]))}</div>`;
    },

    metode: (r) => {
      const s = r.selection;
      return `<h2>Metode terpilih (KUK 3.1)</h2><p class="note">${esc(s.formula)} · ambang ≥ ${s.threshold}</p>
        <div class="card">${table(["Metode", "Lapis / level", "Varian", "Skor", "Target", "Alasan"], s.selected.map((m) =>
          [`<b>${esc(m.method_id)}</b> ${esc(m.name)}`, `${esc(m.layer)} / ${esc(m.level)}`, m.variant === "tereduksi" ? badge("LAYAK VERSI TEREDUKSI") : badge("LAYAK"),
            `<span class="num">${m.score}</span>`, `<span class="mono">${esc((m.weak_targets.length ? m.weak_targets : m.targets).join(", "))}</span>`, esc(m.reason)]))}</div>
        <h3>Metode ditolak</h3><div class="card">${table(["Metode", "Kelayakan", "Skor", "Alasan"], s.rejected.map((m) =>
          [`<b>${esc(m.method_id)}</b> ${esc(m.name)}`, badge(m.feasibility), `<span class="num">${m.score}</span>`, esc(m.reason)]))}</div>
        <h2>Parameter pengujian (KUK 3.2)</h2>${Object.entries(r.parameters).map(([id, p]) => `<h3>${esc(id)}</h3><div class="card">${table(["Parameter", "Nilai"],
          Object.entries(p).map(([k, v]) => [`<code>${esc(k)}</code>`, esc(k === "tests" && typeof v === "object" ? Object.entries(v).map(([t, x]) => `${t} ${fmt(x)}`).join("; ") : fmt(v))]))}</div>`).join("")}`;
    },

    jejak: (r) => `<h2>Matriks keterlacakan</h2><div class="card">${table(["ID", "Persyaratan", "Objek", "Metode uji", "Rujukan", "Kriteria lulus"],
      r.traceability.map((t) => [`<b class="mono">${esc(t.id)}</b>`, esc(t.requirement), esc(t.object), `${esc(t.method_id)} <span class="note">(${esc(t.variant)})</span>`, esc(t.reference), esc(t.pass_criteria)]))}</div>`,

    serangan: (r) => `<h2>Tren serangan relevan (KUK 1.2) ${src("HASIL LITERATUR")}</h2>
      <p class="note">${r.attacks.summary.total} serangan setelah filter profil · ${r.attacks.summary.practical.length} praktis · ${r.attacks.summary.needs_verification.length} perlu verifikasi</p>
      <div class="card">${table(["ID", "Kategori", "Serangan", "Model", "log2 T/D/M", "Ronde", "Status", "Rujukan"], r.attacks.items.map((a) =>
        [`<span class="mono">${esc(a.id)}</span>`, esc(a.category), esc(a.name), esc(a.model),
          `<span class="mono">${["time_log2", "data_log2", "memory_log2"].map((k) => a.complexity[k] ?? "—").join(" / ")}</span>`, esc(a.rounds),
          esc(a.status) + (a.verify === "PERLU_VERIFIKASI" ? ` <span class="tag verify">PERLU_VERIFIKASI</span>` : ""), esc(a.refs.join("; "))]))}</div>`,

    standar: (r) => `<h2>Daftar referensi standar (KUK 1.3)</h2><div class="card">${table(["ID", "Organisasi", "Judul", "Tahun", "Peran"], r.references.map((x) =>
      [`<b class="mono">${esc(x.id)}</b>`, esc(x.org), esc(x.title) + (x.note ? ` <span class="note">(${esc(x.note)})</span>` : "") + (x.verify ? ` <span class="tag verify">PERLU_VERIFIKASI</span>` : ""), esc(x.year), esc(x.role_label)]))}</div>`,

    profil: (r) => {
      const p = r.profile, a = p.algorithm, i = p.implementation;
      return `<h2>Profil produk & ruang lingkup (KUK 1.1)</h2><div class="card">${table(["Atribut", "Nilai"], [
        ["Produk", esc(`${p.product.name} ${p.product.version}`)], ["Deskripsi", esc(p.product.description)],
        ["Algoritma", esc(a.name)], ["Kelas primitif", esc(a.primitive_label)], ["Struktur / mode", esc(`${a.structure} / ${a.mode || "—"}`)],
        ["Parameter", `<span class="mono">${esc(fmt(a.parameters))}</span>`], ["Platform", esc(i.platform_desc || i.platform)],
        ["Bahasa", esc(`${i.language} (+ ${(i.bindings || []).join(", ")})`)], ["RBG", esc(i.rng)],
        ["Catatan implementasi", esc(fmt(a.implementation_notes))], ["Tingkat akses", esc(`${p.tester.access} — ${p.tester.access_desc}`)],
        ["Ruang lingkup", esc(p.tester.scope.join(" · "))], ["Di luar lingkup", esc(p.tester.out_of_scope.join(" · "))]])}</div>`;
    },

    kuk: (r) => `<h2>Peta KUK → bagian dokumen → file kode</h2><div class="card">${table(["KUK", "Deskripsi", "Bagian", "File kode", "Unit test"], r.kuk_map.map((k) =>
      [`<b>${esc(k.kuk)}</b>`, esc(k.desc), esc(k.section), k.files.map((f) => `<code>${esc(f)}</code>`).join("<br>"), k.tests.map((f) => `<code>${esc(f)}</code>`).join("<br>")]))}</div>
      <h3>KAT rinci (${esc(r.kat.algorithm)})</h3><div class="card">${table(["Vektor", "Sumber", "Hasil"], r.kat.cases.map((c) => [`<span class="mono">${esc(c.id)}</span>`, esc(c.source), badge(c.pass ? "LULUS" : "GAGAL")]))}</div>`,
  };

  addEventListener("hashchange", () => {
    const h = location.hash.slice(1);
    if (index && h !== current && index.algorithms.some((a) => a.slug === h)) show(h);
  });
  load();
})();
