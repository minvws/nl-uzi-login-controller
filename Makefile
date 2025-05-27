env = env PATH="${bin}:$$PATH"

venv: .venv/touchfile ## Create virtual environment
.venv/touchfile:
	test -d .venv || poetry install
	touch .venv/touchfile

clean_venv: ## Remove virtual environment
	@echo "Cleaning venv"
	@rm -rf .venv

run:
	docker-compose up -d
	npm run build
	. .venv/bin/activate && ${env} python -m app.main

setup-npm:
	scripts/./setup-npm.sh

setup: venv app.conf oidc-providers-list.json version.json setup-npm

app.conf:
	cp app.conf.example app.conf

oidc-providers-list.json:
	cp oidc-providers-list.json.example oidc-providers-list.json

version.json:
	cp static/version.json.example static/version.json

check:
	poetry run pylint app
	poetry run black --check app tests

audit:
	poetry run bandit -r app

fix:
	poetry run black app tests

test:
	poetry run pytest --cov --cov-report=term --cov-report=xml

type-check:
	poetry run mypy

check-all: fix check type-check test audit
