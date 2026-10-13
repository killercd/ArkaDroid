PYTHON ?= python3

.PHONY: run stop test

run:
	$(PYTHON) scripts/droidboard.py start

stop:
	$(PYTHON) scripts/droidboard.py stop

test:
	$(PYTHON) -m pytest backend/tests
