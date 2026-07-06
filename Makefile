# labforge — convenience targets. Everything is a thin wrapper around the
# scripts/ helpers so you can `make up` instead of remembering flags.

.DEFAULT_GOAL := help
SHELL := /bin/bash

.PHONY: help up minimal windows status isolation halt destroy provision lint

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort | awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

up: ## Bring the full lab up (attacker+siem+targets+fleet)
	@bash scripts/lab-up.sh

minimal: ## Fast lab: attacker + siem + juice only
	@bash scripts/lab-up.sh --minimal

windows: ## Full lab plus the Windows victim
	@bash scripts/lab-up.sh --windows

status: ## Show machine status and endpoints
	@bash scripts/lab-status.sh

isolation: ## Verify the lab is air-gapped (should report all isolated)
	@bash scripts/verify-isolation.sh

provision: ## Re-run Ansible provisioning without recreating VMs
	@vagrant provision

halt: ## Power off all machines (keeps them)
	@vagrant halt

destroy: ## Destroy every machine (irreversible)
	@vagrant destroy -f

lint: ## Lint the Ansible + YAML locally (needs ansible-lint + yamllint)
	@yamllint . && ansible-lint ansible/site.yml
