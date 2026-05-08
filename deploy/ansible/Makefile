.PHONY: help install test deploy deploy-check deploy-prod deploy-staging deploy-dev \
        status verify syntax lint clean

ANSIBLE_INVENTORY ?= inventory/hosts
ANSIBLE_PLAYBOOK ?= site.yml
ANSIBLE_OPTS ?=

help:
	@echo "obs-agent Ansible Deployment Helper"
	@echo ""
	@echo "Available targets:"
	@echo "  make install          - Install Ansible dependencies"
	@echo "  make test             - Test connectivity to all hosts"
	@echo "  make syntax           - Check playbook syntax"
	@echo "  make lint             - Lint playbook (requires ansible-lint)"
	@echo ""
	@echo "  make deploy           - Deploy to all hosts (dry-run first with --check)"
	@echo "  make deploy-check     - Dry-run deployment (check mode)"
	@echo "  make deploy-prod      - Deploy to production only"
	@echo "  make deploy-staging   - Deploy to staging only"
	@echo "  make deploy-dev       - Deploy to development only"
	@echo ""
	@echo "  make status           - Check service status on all hosts"
	@echo "  make verify           - Verify metrics/API endpoints"
	@echo "  make logs             - View recent logs from all hosts"
	@echo ""
	@echo "  make clean            - Remove .retry files"
	@echo ""
	@echo "Usage examples:"
	@echo "  make deploy                    # Deploy to all hosts"
	@echo "  make deploy-prod               # Deploy to production"
	@echo "  make deploy OPTS='--tags config' # Update config only"
	@echo ""

install:
	@echo "Installing Python dependencies..."
	pip install -r requirements.txt
	@echo "Done. Run 'make test' to verify connectivity."

test:
	@echo "Testing connectivity to all hosts..."
	ansible all -i $(ANSIBLE_INVENTORY) -m ping

syntax:
	@echo "Checking playbook syntax..."
	ansible-playbook -i $(ANSIBLE_INVENTORY) $(ANSIBLE_PLAYBOOK) --syntax-check

lint:
	@echo "Linting playbook (requires ansible-lint)..."
	@command -v ansible-lint >/dev/null 2>&1 || { echo "ansible-lint not installed. Install with: pip install ansible-lint"; exit 1; }
	ansible-lint $(ANSIBLE_PLAYBOOK)

deploy-check:
	@echo "Running deployment in check mode (dry-run)..."
	@echo "This will show what changes would be made without making them."
	@echo ""
	ansible-playbook -i $(ANSIBLE_INVENTORY) $(ANSIBLE_PLAYBOOK) --check --diff $(ANSIBLE_OPTS)

deploy: syntax deploy-check
	@echo ""
	@echo "Proceeding with actual deployment..."
	@read -p "Press Enter to continue or Ctrl+C to abort... " dummy
	ansible-playbook -i $(ANSIBLE_INVENTORY) $(ANSIBLE_PLAYBOOK) $(ANSIBLE_OPTS)

deploy-prod:
	@echo "Deploying to production servers only..."
	ansible-playbook -i $(ANSIBLE_INVENTORY) $(ANSIBLE_PLAYBOOK) \
		--limit obs_agents_production $(ANSIBLE_OPTS)

deploy-staging:
	@echo "Deploying to staging servers only..."
	ansible-playbook -i $(ANSIBLE_INVENTORY) $(ANSIBLE_PLAYBOOK) \
		--limit obs_agents_staging $(ANSIBLE_OPTS)

deploy-dev:
	@echo "Deploying to development servers only..."
	ansible-playbook -i $(ANSIBLE_INVENTORY) $(ANSIBLE_PLAYBOOK) \
		--limit obs_agents_development $(ANSIBLE_OPTS)

status:
	@echo "Checking obs-agent service status..."
	ansible obs_agents -i $(ANSIBLE_INVENTORY) -m systemd -a "name=obs-agent"

verify:
	@echo "Verifying metrics endpoints..."
	ansible obs_agents -i $(ANSIBLE_INVENTORY) -m uri \
		-a "url=http://localhost:9200/metrics" --one-line

logs:
	@echo "Fetching recent logs from all hosts..."
	ansible obs_agents -i $(ANSIBLE_INVENTORY) -m command \
		-a "journalctl -u obs-agent -n 20 --no-pager"

clean:
	@echo "Cleaning up temporary files..."
	find . -name "*.retry" -delete
	rm -f .ansible-lint
	@echo "Done."
