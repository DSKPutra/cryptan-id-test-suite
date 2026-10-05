"""Templat PDF (ReportLab Platypus): gaya halaman, tabel, kartu KPI, badge status.

Tidak berisi data — builder.py menyusun isi dari results.json lalu memakai komponen di sini."""
from pathlib import Path
from xml.sax.saxutils import escape

import yaml
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (BaseDocTemplate, Flowable, Frame, KeepTogether, PageTemplate, Paragraph, Spacer, Table,
                                TableStyle)
from reportlab.platypus.tableofcontents import TableOfContents

THEME = yaml.safe_load((Path(__file__).with_name("theme.yaml")).read_text(encoding="utf-8"))
C = {k: colors.HexColor(v) for k, v in THEME["colors"].items() if isinstance(v, str)}
STATUS_COLOR = {k: colors.HexColor(v) for k, v in THEME["colors"]["status"].items()}
OVERALL_COLOR = {k: colors.HexColor(v) for k, v in THEME["colors"]["overall"].items()}
F, S = THEME["fonts"], THEME["sizes"]
MARGIN = THEME["page"]["margin_cm"] * cm
GAP = THEME["page"]["header_gap_cm"] * cm

STATUS_SHORT = {"LULUS": "LULUS", "GAGAL": "GAGAL", "INKONKLUSIF": "INKON", "TIDAK_DAPAT_DIUJI": "TDD",
                "TIDAK_BERLAKU": "T/B", "DICATAT": "CATAT"}
OVERALL_TEXT = {"LULUS_SEMUA": "LULUS SEMUA", "LULUS_SEBAGIAN": "LULUS SEBAGIAN", "TEMUAN": "ADA TEMUAN",
                "TIDAK_DAPAT_DIUJI": "TIDAK DAPAT DIUJI"}


def _register_fonts():
    import matplotlib
    d = Path(matplotlib.get_data_path()) / "fonts" / "ttf"
    for name in F.values():
        if name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(name, str(d / f"{name}.ttf")))
    from reportlab.lib.fonts import addMapping
    for fam, (n, b, i, bi) in {F["body"]: (F["body"], F["bold"], F["italic"], F["bold_italic"]),
                               F["mono"]: (F["mono"], F["mono_bold"], F["mono"], F["mono_bold"])}.items():
        addMapping(fam, 0, 0, n)
        addMapping(fam, 1, 0, b)
        addMapping(fam, 0, 1, i)
        addMapping(fam, 1, 1, bi)


_register_fonts()


def _ps(name, **kw):
    base = dict(fontName=F["body"], fontSize=S["body"], leading=S["body"] * 1.35, textColor=C["text"])
    base.update(kw)
    return ParagraphStyle(name, **base)


ST = {
    "body": _ps("body", spaceAfter=5),
    "bullet": _ps("bullet", leftIndent=12, bulletIndent=2, spaceAfter=3),
    "small": _ps("small", fontSize=S["small"], leading=S["small"] * 1.3, textColor=C["muted"]),
    "h1": _ps("h1", fontName=F["bold"], fontSize=S["h1"], leading=S["h1"] * 1.3, textColor=C["accent"], spaceBefore=4,
              spaceAfter=10, keepWithNext=1),
    "h2": _ps("h2", fontName=F["bold"], fontSize=S["h2"], leading=S["h2"] * 1.3, spaceBefore=10, spaceAfter=5, keepWithNext=1),
    "h3": _ps("h3", fontName=F["bold"], fontSize=S["h3"], leading=S["h3"] * 1.3, spaceBefore=8, spaceAfter=4,
              textColor=C["accent"], keepWithNext=1),
    # keepWithNext=0: KeepTogether dengan tabel panjang memindahkan seluruh tabel ke halaman baru.
    # Sebagai gantinya builder menyisipkan CondPageBreak sebelum judul tabel.
    "caption": _ps("caption", fontName=F["bold"], fontSize=8.5, leading=11, textColor=C["muted"], spaceBefore=4, spaceAfter=3),
    "cell": _ps("cell", fontSize=S["table"], leading=S["table"] * 1.25),
    "cell_b": _ps("cell_b", fontName=F["bold"], fontSize=S["table"], leading=S["table"] * 1.25),
    "cell_mono": _ps("cell_mono", fontName=F["mono"], fontSize=S["table"] - 0.5, leading=S["table"] * 1.25),
    "cell_small": _ps("cell_small", fontSize=S["small"] - 0.5, leading=(S["small"] - 0.5) * 1.25),
    "cell_mono_small": _ps("cell_mono_small", fontName=F["mono"], fontSize=6.3, leading=8),
    "cell_hdr": _ps("cell_hdr", fontName=F["bold"], fontSize=S["table"], leading=S["table"] * 1.25, textColor=colors.white),
    "cell_badge": _ps("cell_badge", fontName=F["bold"], fontSize=S["table"] - 1, leading=S["table"] * 1.15,
                      textColor=colors.white, alignment=TA_CENTER),
    "cover_title": _ps("cover_title", fontName=F["bold"], fontSize=24, leading=30, textColor=C["accent"]),
    "cover_sub": _ps("cover_sub", fontSize=13, leading=18, textColor=C["muted"]),
    "toc0": _ps("toc0", fontName=F["bold"], fontSize=10, leading=15, leftIndent=0),
    "toc1": _ps("toc1", fontSize=9.5, leading=13, leftIndent=14),
    "lot": _ps("lot", fontSize=9, leading=12, leftIndent=0),
    "kpi_num": _ps("kpi_num", fontName=F["bold"], fontSize=20, leading=24, alignment=TA_CENTER, textColor=C["accent"]),
    "kpi_lbl": _ps("kpi_lbl", fontSize=8, leading=10, alignment=TA_CENTER, textColor=C["muted"]),
}


def P(text, style="cell", raw=False):
    """Paragraph aman (teks di-escape kecuali raw=True untuk markup terkendali)."""
    return Paragraph(text if raw else escape(str(text)), ST[style] if isinstance(style, str) else style)


def mono(text, style="cell_mono"):
    return P(text, style)


# --------------------------------------------------------------------------- penanda TOC / bookmark
class Heading(Paragraph):
    """Paragraf judul yang tercatat di daftar isi dan outline PDF."""

    def __init__(self, text, level, key, toc=True):
        super().__init__(escape(text), ST[("h1", "h2", "h3")[min(level, 2)]])
        self.toc_text, self.level, self.key, self.toc = text, level, key, toc


class Caption(Paragraph):
    """Judul tabel/gambar bernomor; tercatat di daftar tabel/gambar."""

    def __init__(self, kind, number, text):
        label = "Tabel" if kind == "table" else "Gambar"
        super().__init__(escape(f"{label} {number}. {text}"), ST["caption"])
        self.kind, self.entry = kind, f"{label} {number}. {text}"


class Anchor(Flowable):
    """Titik bookmark tanpa ukuran (mis. outline kartu algoritme di Bab 5)."""

    def __init__(self, text, level, key):
        super().__init__()
        self.text, self.level, self.key = text, level, key

    def wrap(self, *a):
        return 0, 0

    def draw(self):
        pass


class ListOf(TableOfContents):
    """Daftar tabel / daftar gambar: TableOfContents yang mendengarkan jenis notifikasi lain."""

    def __init__(self, kind):
        super().__init__()
        self.kind = kind
        self.levelStyles = [ST["lot"]]
        self.dotsMinLevel = 0

    def notify(self, kind, stuff):
        if kind == self.kind:
            self.addEntry(*stuff)


def make_toc():
    t = TableOfContents()
    t.levelStyles = [ST["toc0"], ST["toc1"]]
    t.dotsMinLevel = 0
    return t


# --------------------------------------------------------------------------- dokumen & halaman
class NumberedCanvas(rl_canvas.Canvas):
    """Menunda penggambaran header/footer sampai jumlah halaman diketahui ('Halaman X dari Y')."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._saved = []

    def showPage(self):
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved)
        for st in self._saved:
            self.__dict__.update(st)
            if not getattr(self, "_skip_hf", False):
                self._header_footer(total)
            super().showPage()
        super().save()

    def _header_footer(self, total):
        doc = self._doc_meta
        w, h = self._pagesize
        self.saveState()
        self.setStrokeColor(C["accent"])
        self.setLineWidth(0.6)
        self.line(MARGIN, h - GAP - 4, w - MARGIN, h - GAP - 4)
        self.setFont(F["body"], S["header"])
        self.setFillColor(C["text"])
        self.drawString(MARGIN, h - GAP, doc["short_title"])
        self.setFont(F["bold"], S["header"])
        self.setFillColor(STATUS_COLOR["GAGAL"])
        self.drawRightString(w - MARGIN, h - GAP, doc["klasifikasi"])
        self.setStrokeColor(C["grid"])
        self.line(MARGIN, GAP + 10, w - MARGIN, GAP + 10)
        self.setFont(F["body"], S["header"])
        self.setFillColor(C["muted"])
        self.drawString(MARGIN, GAP, doc["penyusun"])
        self.drawCentredString(w / 2, GAP, doc["tanggal"])
        self.drawRightString(w - MARGIN, GAP, f"Halaman {self._pageNumber} dari {total}")
        self.restoreState()


class ReportDoc(BaseDocTemplate):
    def __init__(self, path, meta, **kw):
        super().__init__(str(path), pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=MARGIN, bottomMargin=MARGIN,
                         title=meta["title"], author=meta["penyusun"], subject=meta["subject"], creator=meta["creator"],
                         keywords=meta.get("keywords", ""), **kw)
        self.meta = meta
        pw, ph = A4
        lw, lh = landscape(A4)
        fp = Frame(MARGIN, MARGIN, pw - 2 * MARGIN, ph - 2 * MARGIN, id="p", leftPadding=0, rightPadding=0, topPadding=0,
                   bottomPadding=0)
        fl = Frame(MARGIN, MARGIN, lw - 2 * MARGIN, lh - 2 * MARGIN, id="l", leftPadding=0, rightPadding=0, topPadding=0,
                   bottomPadding=0)
        self.addPageTemplates([
            PageTemplate("cover", [fp], pagesize=A4, onPage=self._on_page(skip=True)),
            PageTemplate("portrait", [fp], pagesize=A4, onPage=self._on_page()),
            PageTemplate("landscape", [fl], pagesize=landscape(A4), onPage=self._on_page()),
        ])
        self._outline_keys = set()

    def _on_page(self, skip=False):
        def f(canv, doc):
            canv._skip_hf = skip
            canv._doc_meta = self.meta
            if skip:
                self._draw_cover_frame(canv)
        return f

    def _draw_cover_frame(self, canv):
        w, h = canv._pagesize
        canv.saveState()
        canv.setFillColor(C["accent"])
        canv.rect(0, h - 1.2 * cm, w, 1.2 * cm, stroke=0, fill=1)
        canv.rect(0, 0, w, 0.5 * cm, stroke=0, fill=1)
        canv.setFillColor(colors.white)
        canv.setFont(F["bold"], 9)
        canv.drawRightString(w - MARGIN, h - 0.75 * cm, self.meta["klasifikasi"])
        canv.drawString(MARGIN, h - 0.75 * cm, "Cryptan.ID Test Suite")
        canv.restoreState()

    def afterFlowable(self, fl):
        if isinstance(fl, Heading):
            key = fl.key
            self.canv.bookmarkPage(key)
            if key not in self._outline_keys:
                self.canv.addOutlineEntry(fl.toc_text, key, level=fl.level, closed=fl.level > 0)
                self._outline_keys.add(key)
            if fl.toc and fl.level <= 1:
                self.notify("TOCEntry", (fl.level, fl.toc_text, self.page, key))
        elif isinstance(fl, Anchor):
            self.canv.bookmarkPage(fl.key)
            if fl.key not in self._outline_keys:
                self.canv.addOutlineEntry(fl.text, fl.key, level=fl.level, closed=True)
                self._outline_keys.add(fl.key)
        elif isinstance(fl, Caption):
            self.notify("LOT" if fl.kind == "table" else "LOF", (0, fl.entry, self.page))

    def handle_documentBegin(self):
        self._outline_keys = set()
        super().handle_documentBegin()


# --------------------------------------------------------------------------- komponen
def data_table(header, rows, widths, zebra=True, extra=None, font_size=None, header_style="cell_hdr"):
    """Tabel dengan header aksen berulang di tiap halaman dan baris selang-seling."""
    hdr = [P(h, header_style) if isinstance(h, str) else h for h in header]
    data = [hdr] + [[c if isinstance(c, Flowable) else P(c) for c in r] for r in rows]
    t = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    cmds = [("BACKGROUND", (0, 0), (-1, 0), C["accent"]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.3, C["grid"]),
            ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5)]
    if zebra:
        for i in range(2, len(data), 2):
            cmds.append(("BACKGROUND", (0, i), (-1, i), C["zebra"]))
    if extra:
        cmds += extra
    t.setStyle(TableStyle(cmds))
    return t


def badge_cmds(col, row, status, palette=None):
    """Perintah TableStyle untuk sel badge: latar warna status (teks status tetap ditulis)."""
    pal = palette or STATUS_COLOR
    c = pal.get(status, C["muted"])
    cmds = [("BACKGROUND", (col, row), (col, row), c), ("VALIGN", (col, row), (col, row), "MIDDLE")]
    return cmds


def badge_par(status, short=False, overall=False):
    txt = (OVERALL_TEXT.get(status, status) if overall else (STATUS_SHORT.get(status, status) if short else status.replace("_", " ")))
    style = ST["cell_badge"]
    if status == "TIDAK_BERLAKU":
        style = ParagraphStyle("b_tb", parent=style, textColor=C["text"])
    return Paragraph(escape(txt), style)


def kpi_cards(items, width):
    """Baris kartu KPI: [(angka, label), …]."""
    n = len(items)
    cells = [[[P(str(v), "kpi_num"), P(lbl, "kpi_lbl")] for v, lbl in items]]
    t = Table(cells, colWidths=[width / n] * n, rowHeights=[2.1 * cm])
    t.setStyle(TableStyle([("BOX", (i, 0), (i, 0), 0.8, C["accent"]) for i in range(n)] +
                          [("BACKGROUND", (0, 0), (-1, -1), C["accent_light"]),
                           ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                           ("LINEAFTER", (0, 0), (-2, 0), 3, colors.white)]))
    return t


def kv_table(pairs, widths, label_bg=True):
    rows = [[P(k, "cell_b"), v if isinstance(v, Flowable) else P(v)] for k, v in pairs]
    t = Table(rows, colWidths=widths, hAlign="LEFT")
    cmds = [("GRID", (0, 0), (-1, -1), 0.3, C["grid"]), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    if label_bg:
        cmds.append(("BACKGROUND", (0, 0), (0, -1), C["accent_light"]))
    t.setStyle(TableStyle(cmds))
    return t


class LogoBox(Flowable):
    """Tempat logo instansi (kotak bertepi putus-putus)."""

    def __init__(self, w=3.2 * cm, h=3.2 * cm, text="tempat logo"):
        super().__init__()
        self.w, self.h, self.text = w, h, text

    def wrap(self, *a):
        return self.w, self.h

    def draw(self):
        c = self.canv
        c.saveState()
        c.setStrokeColor(C["grid"])
        c.setDash(3, 3)
        c.roundRect(0, 0, self.w, self.h, 6)
        c.setFont(F["body"], 8)
        c.setFillColor(C["muted"])
        c.drawCentredString(self.w / 2, self.h / 2 - 3, self.text)
        c.restoreState()


__all__ = ["THEME", "C", "STATUS_COLOR", "OVERALL_COLOR", "ST", "P", "mono", "Heading", "Caption", "Anchor", "ListOf", "make_toc",
           "NumberedCanvas", "ReportDoc", "data_table", "badge_cmds", "badge_par", "kpi_cards", "kv_table", "LogoBox", "Spacer",
           "cm", "TA_LEFT", "TA_RIGHT", "escape"]
