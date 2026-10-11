.PHONY: install dev test lint format typecheck security build
install dev test lint format typecheck security build:
	python scripts/dev.py $@
