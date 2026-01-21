# Makefile - Common syslog generator commands

.PHONY: help switch list test run dev staging prod install clean

# Default target
help:
	@echo "Syslog Generator - Available Commands"
	@echo ""
	@echo "Target Management:"
	@echo "  make list          - List all ES targets"
	@echo "  make switch T=dev  - Switch to target"
	@echo "  make test          - Test current target connection"
	@echo "  make current       - Show current target"
	@echo ""
	@echo "Quick Switch:"
	@echo "  make dev           - Switch to dev"
	@echo "  make staging       - Switch to staging"
	@echo "  make prod          - Switch to prod"
	@echo ""
	@echo "Run Generator:"
	@echo "  make run           - Run with current config"
	@echo "  make run-dev       - Switch to dev and run"
	@echo "  make run-prod      - Switch to prod and run"
	@echo "  make run-burst     - Run in burst mode"
	@echo ""
	@echo "Setup:"
	@echo "  make install       - Install dependencies"
	@echo "  make setup         - Create .env from template"
	@echo "  make clean         - Clean generated files"

# Target management
list:
	@python switch_target.py --list

switch:
ifndef T
	@echo "Usage: make switch T=<target>"
	@echo "Example: make switch T=prod"
else
	@python switch_target.py --switch $(T)
endif

test:
	@python switch_target.py --test

current:
	@python switch_target.py --current

# Quick switches
dev:
	@python switch_target.py --switch dev

staging:
	@python switch_target.py --switch staging

prod:
	@echo "⚠️  Switching to PRODUCTION"
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ] && python switch_target.py --switch prod

# Run commands
run:
	python -m syslog_generator.main

run-dev: dev
	python -m syslog_generator.main

run-staging: staging
	python -m syslog_generator.main

run-prod: prod
	python -m syslog_generator.main

run-burst:
	python -m syslog_generator.main --burst

run-quiet:
	python -m syslog_generator.main --es-only

# With specific rates
run-slow:
	python -m syslog_generator.main --rate 1

run-fast:
	python -m syslog_generator.main --rate 100

run-stress:
	python -m syslog_generator.main --rate 1000

# Setup
install:
	pip install -r requirements.txt

setup:
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "✓ Created .env from .env.example"; \
		echo "  Edit .env with your configuration"; \
	else \
		echo "⚠ .env already exists"; \
	fi

clean:
	rm -rf logs/*.log
	rm -rf __pycache__
	rm -rf syslog_generator/__pycache__
	find . -name "*.pyc" -delete
