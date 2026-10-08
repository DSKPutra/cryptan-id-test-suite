/* Cryptan.ID Test Suite — dashboard UK-3 (membaca data/uk3/<produk>/…, hasil uji langsung uk3_pengujian). */
(() => {
  const SETS = [
    { id: "securefile", label: "Produk latihan", name: "SecureFile v1.0 & v1.1", sub: "TC-01…TC-09, TC-06 nonce/salt" },
    { id: "pustaka", label: "Pustaka acuan", name: "pyca/cryptography", sub: "TC-BC/AE/SC/H/PK/DS · Lab 1 E2–E4" },
    { id: "lab", label: "Lab", name: "Lab Keacakan", sub: "Golomb · five basic · SP 800-22" },
  ];
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const CLS = { LULUS: "OK", GAGAL: "TIDAK", TERBLOKIR: "RED", "TIDAK DAPAT DIUJI": "muted", Memenuhi: "OK", "Memenuhi dengan Catatan": "RED",
    "Tidak Memenuhi": "TIDAK", Inkonklusif: "muted", Ya: "OK", Tidak: "TIDAK", "Terima H₀": "OK", "Tolak H₀": "TIDAK" };
  const b = (s) => `<span class="b ${CLS[s] ?? "muted"}">${esc(s)}</span>`;
  const n4 = (x) => (x === null || x === undefined ? "—" : Number(x).toFixed(4).replace(".", ","));
  const table = (h, rows) => `<div class="tbl"><table><thead><tr>${h.map((x) => `<th>${esc(x)}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  const root = document.documentElement;
  try { const t = localStorage.getItem("cryptan-theme"); if (t) root.dataset.theme = t; } catch (e) {}
  $("#theme").onclick = () => {
    const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
    try { localStorage.setItem("cryptan-theme", root.dataset.theme); } catch (e) {}
  };
  const cache = {};
  let cur = null, tab = "ringkas";
  const get = async (p) => (cache[p] ||= await (await fetch(p)).json());
  const getText = async (p) => (cache[p] ||= await (await fetch(p)).text());

  $("#sets").innerHTML = SETS.map((s) => `<button class="algo" data-s="${s.id}" aria-selected="false"><div class="prim">${esc(s.label)}</div>
    <div class="name">${esc(s.name)}</div><div class="row"><span class="b muted">${esc(s.sub)}</span></div></button>`).join("");
  $$("#sets .algo").forEach((x) => (x.onclick = () => show(x.dataset.s)));

  const TABS = [["ringkas", "Kesimpulan (KUK 3.2)"], ["lembar", "Lembar hasil (KUK 2.2)"], ["olah", "Olah data (KUK 3.1)"],
    ["temuan", "Temuan & CVSS"], ["siap", "Persiapan (KUK 1.1–1.2)"], ["tahap", "Tahapan (KUK 2.1)"], ["log", "Log"], ["bukti", "Bukti"]];

  async function show(id) {
    cur = id;
    history.replaceState(null, "", "#" + id);
    $$("#sets .algo").forEach((x) => x.setAttribute("aria-selected", x.dataset.s === id));
    try {
      if (id === "lab") return renderLab(await get("data/uk3/lab.json"));
      const base = `data/uk3/${id}/`;
      const [H, K, A, R, P, I] = await Promise.all(["uk3_hasil_uji", "kesimpulan", "analisis", "run", "prep", "runs_index"].map((f) => get(base + f + ".json")));
      render({ H, K, A, R, P, I, base });
    } catch (e) {
      $("#err").hidden = false; $("#err").textContent = "Gagal memuat data UK-3 — jalankan `python -m uk3_pengujian export-web`.";
    }
  }

  function render(D) {
    const { H, K, R, base } = D;
    const vers = Object.keys(H.versi);
    $("#detail").innerHTML = `
      <div class="stats">${vers.map((v) => { const x = H.versi[v]; return `<div class="stat"><div class="k">v${esc(v)} · ${esc(x.label)}</div>
        <div class="v">${x.rekap.LULUS}/${Object.values(x.rekap).reduce((a, c) => a + c, 0)}</div><div class="s">${b(x.keseluruhan)}</div></div>`; }).join("")}
        <div class="stat"><div class="k">Temuan</div><div class="v">${H.temuan.length}</div><div class="s">${H.temuan.map((f) => esc(f.id + " · " + (f.cvss_score ?? "—"))).join(", ") || "—"}</div></div>
        <div class="stat"><div class="k">Bukti</div><div class="v">${H.evidence_manifest_ok ? "cocok" : "TIDAK cocok"}</div><div class="s">run ${esc(H.run_id)}</div></div>
      </div>
      <div class="dl">
        <a href="${base}Laporan_Hasil_Pengujian.pdf" download>⬇ Laporan (.pdf)</a>
        <a href="${base}Laporan_Hasil_Pengujian.docx" download>⬇ Laporan (.docx)</a>
        <a href="${base}uk3_hasil_uji.json" download>⬇ uk3_hasil_uji.json (UK-4)</a>
        <a href="${base}lembar_hasil.csv" download>⬇ lembar_hasil.csv</a>
        <a href="${base}evidence_manifest.json" download>⬇ evidence_manifest.json</a>
      </div>
      <div class="tabs" role="tablist">${TABS.map(([k, l]) => `<button role="tab" data-t="${k}" aria-selected="${k === tab}">${esc(l)}</button>`).join("")}</div>
      <div id="tabbody"></div>`;
    $$(".tabs button").forEach((x) => (x.onclick = () => { tab = x.dataset.t; render(D); }));
    $("#tabbody").innerHTML = body(D, vers);
    if (tab === "log") {
      const sel = $("#logsel");
      const load = async () => { $("#logtxt").textContent = await getText(base + sel.value); };
      sel.onchange = load; load();
    }
  }

  function body(D, vers) {
    const { H, K, A, R, P, I } = D;
    if (tab === "ringkas") return vers.map((v) => { const x = K.per_versi[v]; return `<h3>v${esc(v)} — ${b(x.keseluruhan)}</h3>` +
      table(["Sasaran", "Uraian", "Kategori", "Alasan"], Object.entries(x.sasaran).sort().map(([s, o]) => [esc(s), esc(o.nama), b(o.kategori), esc(o.alasan)])); }).join("") +
      `<h3>Rumusan</h3><ul>${K.pernyataan.map((s) => `<li>${esc(s)}</li>`).join("")}</ul><p class="note">${esc(K.aturan_agregasi)}. Kesimpulan dibatasi pada versi, metode, dan TC yang dijalankan.</p>`;
    if (tab === "lembar") {
      const rows = R.versi[vers[0]].tc.map((t, i) => [`<code>${esc(t.id)}</code>`, esc(t.judul), esc(t.tahap), esc(t.jenis),
        ...vers.map((v) => b(R.versi[v].tc[i].status)), vers.map((v) => R.versi[v].tc[i].status !== "LULUS" ? `v${esc(v)}: ${esc(R.versi[v].tc[i].actual)}` : "").filter(Boolean).join("<br>")]);
      return table(["TC", "Judul", "Tahap", "Jenis", ...vers.map((v) => "v" + v), "Catatan"], rows);
    }
    if (tab === "olah") return A.metode.map((m) => `<h3>${esc(m.metode)}</h3><p class="note">Aturan: ${esc(m.aturan)}</p>` +
      table(["Versi", "TC", "Status", "Olah data"], m.baris.map((x) => [esc(x.versi), `<code>${esc(x.tc)}</code>`, b(x.status), esc(x.olah)]))).join("") +
      `<p class="note">Keputusan TC ${A.konsisten ? "konsisten" : "TIDAK konsisten"} dengan olah data.</p>`;
    if (tab === "temuan") return K.temuan.length ? K.temuan.map((f) => `<h3>${esc(f.id)} · ${esc(f.judul)} (v${esc(f.versi)})</h3>` +
      table(["Field", "Isi"], [["Test case", esc(f.test_case)], ["Bukti", esc(f.bukti)], ["Dampak", esc(f.dampak)], ["Acuan", esc(f.acuan)],
        ["Keparahan", esc(f.keparahan)], ["Rekomendasi", esc(f.rekomendasi)]]) +
      (f.cvss ? table(["Langkah", "Perhitungan", "Hasil"], f.cvss.langkah.map((l) => l.map(esc))) : "") +
      (f.demonstrasi_dampak && f.demonstrasi_dampak.berhasil ? `<p class="note">C1 ⊕ C2 = P1 ⊕ P2 → P2 “${esc(f.demonstrasi_dampak.p2_diketahui)}” diketahui → P1 dipulihkan “${esc(f.demonstrasi_dampak.p1_dipulihkan)}”.</p>` : "")).join("")
      : `<p class="note">Tidak ada TC yang GAGAL.</p>`;
    if (tab === "siap") return `<h3>Checklist kesiapan</h3>` + table(["Butir", "Status", "Kekurangan"], P.checklist.items.map((i) => [esc(i.uraian), b(i.status), esc(i.kekurangan ?? "—")])) +
      `<p class="note">${esc(P.checklist.keputusan)}</p><h3>Dokumen uji</h3>` + table(["Jenis", "Berkas", "Asal", "SHA-256"], P.dokumen.map((d) => [esc(d.jenis), `<code>${esc(d.berkas)}</code>`, esc(d.asal), `<code>${esc((d.sha256 || "—").slice(0, 16))}</code>`])) +
      `<h3>Perangkat & verifikasi alat</h3><p><code>${esc(P.inventaris.catatan_lingkungan)}</code></p>` +
      table(["Uji", "Expected", "Aktual", "Hasil"], P.inventaris.verifikasi.map((c) => [esc(c.uji), `<code>${esc(c.expected.slice(0, 20))}</code>`, `<code>${esc(c.actual.slice(0, 20))}</code>`, b(c.lulus ? "LULUS" : "GAGAL")]));
    if (tab === "tahap") return table(["Tahap", "Nama", "Alasan", "TC"], R.rencana.tahapan.map((s) => [esc(s.tahap), esc(s.nama), esc(s.alasan), esc(s.tc.join(", "))])) +
      `<p class="note">${R.rencana.negatif} dari ${R.rencana.jumlah} TC adalah uji negatif. ${R.rencana.peringatan.map(esc).join(" ")}</p>`;
    if (tab === "log") return `<select id="logsel">${vers.map((v) => `<option>${esc(R.versi[v].log)}</option>`).join("")}</select><pre id="logtxt" class="log"></pre>`;
    if (tab === "bukti") return `<h3>Riwayat semua percobaan</h3>` + table(["Run ID", "Mulai", "Alasan", "Deviasi"], I.map((x) => [`<code>${esc(x.run_id)}</code>`, esc(x.mulai), esc(x.alasan), esc(x.deviasi)])) +
      `<p class="note">Verifikasi lokal: <code>python -m uk3_pengujian verify-evidence --product ${esc(cur)} --run ${esc(H.run_id)}</code></p>`;
    return "";
  }

  function renderLab(L) {
    const b5 = (r) => table(["Uji", "Statistik", "Nilai", "Kritis (α = 0,01)", "p-value", "Keputusan"], r.tests.map((t) =>
      [esc(t.test), esc(t.statistic_name), n4(t.statistic), n4(t.critical), n4(t.p_value), b(t.decision)]));
    const g = L.golomb_100;
    $("#detail").innerHTML = `<p class="note">Semua angka dihitung ulang oleh <code>uk3_pengujian</code> (HASIL UJI LANGSUNG) dan dicek pytest terhadap materi.
      Five basic tests hanya untuk studi kasus; hasil resmi memakai NIST STS lengkap. Lolos uji keacakan adalah syarat perlu, bukan syarat cukup.</p>
      <h3>Barisan 100 bit (random.Random(13).randint)</h3><p><code>${esc(L.barisan_100)}</code></p>${b5(L.basic5_100)}
      <p class="note">Golomb: G1 ${g.G1.ok ? "✓" : "✗"} (n₀ = ${g.G1.n0}, n₁ = ${g.G1.n1}) · G2 ${g.G2.ok ? "✓" : "✗"} (${g.G2.runs} run siklik) · G3 ${g.G3.ok ? "✓" : "✗"} — ${esc(g.conclusion)}</p>
      ${table(["τ", ...Object.keys(g.G3.C)], [["C(τ)", ...Object.values(g.G3.C).map((v) => v.toFixed(2).replace(".", ","))]])}
      <h3>Pembanding: pola 1100 berulang</h3>${b5(L.basic5_1100)}
      <h3>m-sequence x⁴ + x + 1 dan latihan LFSR 5 tahap (tap 3 & 5)</h3>
      ${table(["Barisan", "G1", "G2", "G3", "Kompleksitas linear", "Polinomial karakteristik"], [L.msequence, L.lfsr5].map((x) =>
        [`<code>${esc(x.bits)}</code>`, b(x.golomb.G1.ok ? "Ya" : "Tidak"), b(x.golomb.G2.ok ? "Ya" : "Tidak"), b(x.golomb.G3.ok ? "Ya" : "Tidak"), esc(x.bm.L), esc(x.bm.characteristic)]))}
      <h3>SP 800-22 — contoh dokumen dengan langkah</h3>${L.sp80022_contoh.map((t) => `<h4>${esc(t.name)} — p = ${n4(t.p_value)}</h4>` +
        table(["Langkah", "Perhitungan", "Hasil"], t.steps.map((s) => s.map(esc)))).join("")}
      <h3>Olah data</h3>${table(["Butir", "Hasil"], [
        ["Proporsi m = 100", `batas bawah ${n4(L.proporsi[0].low)}`], ["Proporsi m = 1000", `${n4(L.proporsi[1].low)} – ${n4(L.proporsi[1].high)}`],
        ["Keseragaman F = 12,8,9,11,10,10,9,11,12,8", `χ² = ${n4(L.keseragaman.chi2)}, P-value_T = ${n4(L.keseragaman.p_value_T)}`],
        ["Welch t (verifikasi PIN)", `t = ${L.welch.t.toFixed(2).replace(".", ",")} → ${L.welch.leak ? "indikasi bocor" : "tidak ada indikasi"}`],
        ["Selang 95% (10 dekripsi)", `${L.ci.mean.toFixed(3)} ± ${L.ci.half_width.toFixed(3)} s`.replaceAll(".", ",")],
        ["Min-entropy P(1) = 0,6", `${L.min_entropy.h_min.toFixed(3).replace(".", ",")} bit; ${L.min_entropy.raw_bits_256} bit mentah untuk 256 bit`],
        ["CVSS 3.1 F-01", `${esc(L.cvss.vector)} → ${L.cvss.base_score} (${esc(L.cvss.severity)})`]].map((r) => r.map((c) => c)))}
      <h3>Pengaruh panjang barisan (m = 100, seed ${L.panjang_barisan.seed})</h3>
      ${table(["n", "Generator", "Monobit", "Runs", "Kesimpulan"], L.panjang_barisan.rows.map((r) => [esc(r.n.toLocaleString("id-ID")), esc(r.generator),
        n4(r.monobit).slice(0, 4), n4(r.runs).slice(0, 4), esc(r.kesimpulan)]))}<p class="note">${esc(L.panjang_barisan.lesson)}</p>`;
  }
  const h = location.hash.slice(1);
  show(SETS.some((s) => s.id === h) ? h : "securefile");
})();
