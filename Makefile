.PHONY: test

clean: clean-build clean-pyc clean-test ## remove all build, test, coverage and Python artifacts

clean-build: ## remove build artifacts
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -f {} +
	rm -f *.whl

clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test: ## remove test and coverage artifacts
	rm -fr .tox/
	rm -f .coverage
	rm -fr htmlcov/
	rm -fr .pytest_cache

setup:
	scripts/config.sh
	make git-hooks

test:
	pip3 install -e .[testing]
	pytest --verbose \
	    --junit-xml reports/$(TOX_ENV_NAME)/tests.xml \
	    --cov-config=.coveragerc \
	    --cov=fuzzerest \
	    --cov-report xml:reports/$(TOX_ENV_NAME)/coverage.xml \
	    --log-level=DEBUG \
	    test

test-all:
	pip install tox
	tox -e ALL -v --recreate -c tox.ini

run-mockserver:
	python3 -m test.mockserver

kill-mockserver:
	wget http://0.0.0.0:8080/die

lint: clean install-pre-commit
	pre-commit run --all-files --verbose

install-pre-commit:
	pip install pre-commit
	pre-commit --version

git-hooks: install-pre-commit
	pre-commit install
