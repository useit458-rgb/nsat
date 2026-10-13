.PHONY: help install test lint run clean docker-build docker-run package

help:
	@echo "Network Security Assessment Toolkit (NSAT)"
	@echo "Available commands:"
	@echo "  make install      - Install dependencies in virtual environment"
	@echo "  make test         - Run test suite with pytest"
	@echo "  make lint         - Check code quality with ruff"
	@echo "  make run          - Start local development server on 127.0.0.1:5000"
	@echo "  make clean        - Remove caches, temporary files, and test artifacts"
	@echo "  make docker-build - Build Docker container image"
	@echo "  make docker-run   - Run container with compose"
	@echo "  make package      - Generate downloadable ZIP archive of the toolkit"

install:
	python3 -m venv venv
	./venv/bin/pip install --upgrade pip
	./venv/bin/pip install -r requirements.txt

test:
	./venv/bin/pytest -v --cov=app --cov-report=term-missing

lint:
	./venv/bin/ruff check app tests

run:
	./venv/bin/python wsgi.py

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -exec rm -rf {} +
	rm -rf .coverage htmlcov

docker-build:
	docker compose build

docker-run:
	docker compose up

package:
	python3 scripts/package_project.py
