PYTHON ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: install dev test lint doctor run scan init clean wipe

install:
	$(PYTHON) -m pip install --user -e .

dev:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install -U pip
	$(BIN)/pip install -e ".[dev]"

test:
	$(BIN)/pytest tests -q

lint:
	$(BIN)/ruff check hunterx tests || true

doctor:
	$(BIN)/hunterx doctor

init:
	$(BIN)/hunterx init

scan:
	$(BIN)/hunterx scan $(TARGET)

run: init doctor
	$(BIN)/hunterx scan $(TARGET)

clean:
	$(BIN)/hunterx clean --all --yes

wipe:
	rm -rf data reports log .venv .pytest_cache .ruff_cache hunterx.egg-info