# Contributing to CloudHop

Thank you for your interest in contributing!

## Reporting Bugs

1. Search [existing issues](https://github.com/husamsoboh-cyber/cloudhop/issues) first.
2. If none found, open a new issue using the **Bug Report** template.
3. Include your OS, Python version, CloudHop version, and rclone version.
4. Attach relevant log output if available.

## Development Setup

```bash
git clone https://github.com/husamsoboh-cyber/cloudhop.git
cd cloudhop
pip install -e .
python -m cloudhop
```

No external dependencies are required beyond the standard library and rclone.

## Running Tests

```bash
pytest
```

Tests live in the `tests/` directory. Add tests for any new behaviour.

## Submitting a Pull Request

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/my-change`
3. Commit your changes with a clear message.
4. Push to your fork and open a PR against `main`.
5. Describe what your PR does and reference any related issues.

## Code Style

- Standard library only — no third-party runtime dependencies.
- Use type hints on all function signatures.
- Keep functions small and focused.
- Follow PEP 8 naming conventions.
