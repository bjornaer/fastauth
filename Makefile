.PHONY: install test lint format clean

install:
	poetry install

test:
	poetry run pytest tests/ -v

test-cov:
	poetry run pytest tests/ --cov=fastauth --cov-report=term-missing

lint:
	poetry run ruff fastauth/ tests/
	poetry run black --check fastauth/ tests/
	poetry run isort --check-only fastauth/ tests/

format:
	poetry run ruff fastauth/ tests/ --fix
	poetry run black fastauth/ tests/
	poetry run isort fastauth/ tests/

clean:
	rm -rf .pytest_cache .coverage .mypy_cache .ruff_cache dist build
