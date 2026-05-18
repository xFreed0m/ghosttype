# ghosttype dev targets. `make check` is the gate CI runs — keep the two in
# sync (see .github/workflows/ci.yml).

PY ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: venv install test cov check lint clean

venv:
	$(PY) -m venv $(VENV)

install: venv
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[dev]"

test:
	$(BIN)/pytest -q

# Coverage with the >=95% line/branch floor enforced (fail_under lives in
# pyproject.toml [tool.coverage.report]; --cov-fail-under makes it explicit
# so the command is self-documenting and CI-independent).
cov:
	$(BIN)/pytest --cov=ghosttype --cov-report=term-missing --cov-fail-under=95 -q

# The gate. Identical to the CI job. A green `make check` == a green CI run.
check: cov

clean:
	rm -rf .pytest_cache .coverage htmlcov **/__pycache__ ghosttype/__pycache__ tests/__pycache__
