PY ?= .venv/bin/python
PROFILE ?= config/product_profile.yaml
REPO ?= https://github.com/

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

site: run           ## bangun dashboard statis → site/
	$(PY) scripts/build_site.py --repo $(REPO)

serve: site
	python3 -m http.server 8000 --directory site

clean:
	rm -rf site .pytest_cache **/__pycache__
