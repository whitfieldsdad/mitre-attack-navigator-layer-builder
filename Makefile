build: requirements

requirements:
	poetry export -f requirements.txt --output requirements.txt --without-hashes

test:
	poetry run pytest -vv tests/
