# Security Analyser

A starter scaffold for a security analysis tool. This repository provides a
clean, well-structured Python project skeleton ready to be fleshed out with
concrete scanning capabilities (static analysis, dependency/CVE checks,
configuration auditing, etc.).

## Status

🚧 **Scaffold** — the project structure, CLI entry point, tests, and CI are in
place. The analysis logic is intentionally minimal and meant to be extended.

## Project layout

```
Security-Analyser/
├── src/
│   └── security_analyser/
│       ├── __init__.py       # package metadata
│       ├── analyser.py       # core analysis logic (stub)
│       └── cli.py            # command-line entry point
├── tests/
│   └── test_analyser.py      # unit tests
├── .github/
│   └── workflows/
│       └── ci.yml            # lint + test on push / PR
├── pyproject.toml            # build config & dependencies
├── requirements-dev.txt      # development dependencies
├── .gitignore
├── LICENSE
└── README.md
```

## Getting started

Requires Python 3.9+.

```bash
# Install in editable mode with dev dependencies
python -m pip install -e .
python -m pip install -r requirements-dev.txt

# Run the CLI
security-analyser --help
security-analyser scan .

# Run the tests
pytest
```

## Development

```bash
# Lint
ruff check .

# Run tests
pytest -q
```

## Extending the scaffold

The scanning logic lives in `src/security_analyser/analyser.py`. The
`Analyser.scan()` method returns a list of `Finding` objects. To add a real
check, implement a rule that inspects the target and appends `Finding`
instances. The CLI in `cli.py` already wires argument parsing to the analyser
and formats the results.

## License

Released under the [MIT License](LICENSE).
