set shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

install:
    python -m pip install --upgrade pip
    python -m pip install -e .[dev]

run:
    python -m cve_agent.cli serve --host 127.0.0.1 --port 8080

test:
    python -m pytest -q

lint:
    ruff check .

format-check:
    ruff format --check .

smoke:
    python scripts/smoke_test.py

validate:
    just lint
    just format-check
    just test
    just smoke

run-demo:
    python -m cve_agent.cli demo
    python -m cve_agent.cli serve --host 127.0.0.1 --port 8080

