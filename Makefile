PY ?= .venv/bin/python
PROFILE ?= config/product_profile.yaml
REPO ?= https://github.com/DSKPutra/cryptan-id-test-suite

.PHONY: install kat run quick test site serve clean

install:            ## buat venv & pasang dependensi
	python3 -m venv .venv && $(PY) -m pip install -q -r requirements.txt

kat:                ## Known Answer Test implementasi referensi core/
	$(PY) -m core.kat

run:                ## UK-1 end-to-end (semua algoritma)
	$(PY) -m uk1_metode --profile $(PROFILE)

quick:              ## UK-1 mode cepat
	$(PY) -m uk1_metode --profile $(PROFILE) --quick

test:               ## unit test (pytest)
	$(PY) -m pytest

site: run catalog-web uk2 ## bangun dashboard statis → site/
	$(PY) scripts/build_site.py --repo $(REPO)

serve: site
	python3 -m http.server 8000 --directory site

clean:
	rm -rf site .pytest_cache **/__pycache__

.PHONY: catalog catalog-scrape catalog-web catalog-gui
PICKS = $(shell grep -v '^\#' samples/input/dropdown_picks.txt | sed 's/.*/"&"/' | tr '\n' ' ')

catalog-scrape:     ## perbarui katalog dari NIST (robots.txt dihormati; offline → seed)
	$(PY) -m algo_catalog scrape --refresh

catalog:            ## susun daftar algoritma uji produk dari samples (file + dropdown) & tautkan ke product_profile.yaml
	$(PY) -m algo_catalog select --file samples/input/datasheet_securelib.pdf samples/input/vendor_page.html \
	  samples/input/securelib_crypto.c samples/input/CryptoService.java samples/input/app_crypto.py --pick $(PICKS) --yes

catalog-web:        ## ekspor katalog untuk dashboard
	$(PY) -m algo_catalog export-web --out web/data/catalog.json

catalog-gui:        ## GUI Streamlit
	$(PY) -m streamlit run algo_catalog/app.py

.PHONY: uk2 uk2-samples uk2-templates
uk2:                ## UK-2 Menyusun Skenario Pengujian (produk)
	$(PY) -m uk2_skenario --profile config/product_profile.yaml --uk1 outputs/uk1

uk2-samples:        ## UK-2 pada 3 profil sampel materi (ECDSA token, TLS 1.3, HSM-X SL 3)
	$(PY) -m uk2_skenario --samples

uk2-templates:      ## ekstrak ulang templat dari materi PPTX lokal (docs/materi/)
	$(PY) scripts/extract_uk2_templates.py

.PHONY: std-report std-report-full std-report-gui
PENYUSUN ?= Dea Saka Kurnia Putra
std-report:         ## daftar algoritme standar + semua uji (mode ringan) + PDF/HTML/XLSX
	$(PY) -m std_report all --pdf --html --xlsx --penyusun "$(PENYUSUN)"

std-report-full:    ## mode full (100 × 10⁶ bit, 10.000 sampel avalanche) — lama
	$(PY) -m std_report run --mode full && $(PY) -m std_report report --pdf --penyusun "$(PENYUSUN)"

std-report-gui:     ## GUI Streamlit dengan Export to PDF
	$(PY) -m streamlit run std_report/app.py

.PHONY: uk3 uk3-gui
uk3:                ## UK-3 alur lengkap: prep → run → analyze → conclude → report (SecureFile + pustaka) → data dashboard
	for p in securefile pustaka; do \
	  $(PY) -m uk3_pengujian prep --product $$p && \
	  $(PY) -m uk3_pengujian run --product $$p --alasan "$${ALASAN:-run via make uk3}" && \
	  $(PY) -m uk3_pengujian analyze --product $$p && $(PY) -m uk3_pengujian conclude --product $$p && \
	  $(PY) -m uk3_pengujian report --product $$p --pdf --docx || exit 1; done
	$(PY) -m uk3_pengujian export-web

uk3-gui:            ## GUI Streamlit UK-3
	$(PY) -m streamlit run uk3_pengujian/app.py
