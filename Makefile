env = env PATH="${bin}:$$PATH"

venv: .venv/touchfile ## Create virtual environment
.venv/touchfile:
	test -d .venv || python3 -m venv .venv
	. .venv/bin/activate; pip install -U pip
	. .venv/bin/activate; pip install pip-tools
	. .venv/bin/activate && ${env} pip-compile --extra dev
	. .venv/bin/activate && ${env} pip-sync
	. .venv/bin/activate && ${env} pip install -e .
	touch .venv/touchfile

clean_venv: ## Remove virtual environment
	@echo "Cleaning venv"
	@rm -rf .venv

run:
	docker-compose up -d
	npm run build
	. .venv/bin/activate && ${env} python -m app.main

pip-sync: ## synchronizes the .venv with the state of requirements.txt
	. .venv/bin/activate && ${env} pip-compile --extra dev
	. .venv/bin/activate && ${env} pip-sync
	. .venv/bin/activate && ${env} pip install -e .

setup-npm:
	scripts/./setup-npm.sh

setup: venv app.conf oidc-providers-list.json version.json setup-npm

app.conf:
	cp app.conf.example app.conf

oidc-providers-list.json:
	cp oidc-providers-list.json.example oidc-providers-list.json

version.json:
	cp static/version.json.example static/version.json

lint:
	. .venv/bin/activate && ${env} pylint app
	. .venv/bin/activate && ${env} black --check app

audit:
	. .venv/bin/activate && ${env} bandit app

fix:
	. .venv/bin/activate && $(env) black app tests

test: venv setup
	. .venv/bin/activate && ${env} pytest tests

type-check:
	. .venv/bin/activate && ${env} MYPYPATH=stubs/ mypy --disallow-untyped-defs --show-error-codes app

coverage:
	. .venv/bin/activate && ${env} coverage run -m pytest tests && coverage report && coverage html

check-all: fix lint type-check test audit
