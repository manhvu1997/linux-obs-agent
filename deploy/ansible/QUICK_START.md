# Quick Start Guide - obs-agent Ansible Deployment

Get obs-agent deployed in 5 minutes.

## 1. Prerequisites Check

```bash
# Ensure you have Ansible and obs-agent binary
ansible --version          # Should be 2.10+
ls -la ../../build/obs-agent  # Binary should exist
```

## 2. Setup (2 minutes)

```bash
# Enter Ansible directory
cd deploy/ansible

# Create inventory
cp inventory/hosts.example inventory/hosts

# Create group variables
cp group_vars/obs_agents.yml.example group_vars/obs_agents.yml

# Test connectivity
ansible all -i inventory/hosts -m ping
```

## 3. Configure

**Edit `inventory/hosts`:**
```ini
[obs_agents]
your-server-01 ansible_host=10.0.1.10
your-server-02 ansible_host=10.0.1.11
```

**Edit `group_vars/obs_agents.yml`:** (optional)
```yaml
obs_agent:
  log_level: "info"           # Change to "debug" for troubleshooting
obs_agent_mongo.enabled: true # If using MongoDB
```

## 4. Deploy (1 minute)

```bash
# Dry-run (check mode)
ansible-playbook -i inventory/hosts site.yml --check

# Deploy
ansible-playbook -i inventory/hosts site.yml

# Deploy to specific servers
ansible-playbook -i inventory/hosts site.yml --limit prod-01
```

## 5. Verify (1 minute)

```bash
# Check service status
ansible obs_agents -i inventory/hosts -m systemd -a "name=obs-agent"

# Check metrics endpoint
curl -s http://localhost:9200/metrics | head -20

# Check diagnose API
curl -s http://localhost:9200/api/diagnose | jq .
```

## Common Commands

```bash
# Update config only (no binary change)
ansible-playbook -i inventory/hosts site.yml --tags config

# Update with debug logging
ansible-playbook -i inventory/hosts site.yml \
  -e "obs_agent.log_level=debug"

# View logs
ssh your-server-01 sudo journalctl -u obs-agent -f

# Status on all servers
ansible obs_agents -i inventory/hosts -m systemd -a "name=obs-agent"

# Batch deploy (5 servers at a time)
ansible-playbook -i inventory/hosts site.yml --serial 5

# Rolling deploy (1 at a time)
ansible-playbook -i inventory/hosts site.yml --serial 1
```

## Environment-Specific Deployment

```bash
# Production
ansible-playbook -i inventory/hosts site.yml --limit obs_agents_production

# Staging
ansible-playbook -i inventory/hosts site.yml --limit obs_agents_staging

# Development
ansible-playbook -i inventory/hosts site.yml --limit obs_agents_development
```

## Troubleshooting

```bash
# Debug mode
ansible-playbook -i inventory/hosts site.yml -vvv

# Check config syntax
yaml.safe_load < group_vars/obs_agents.yml

# Verify generated config
ssh your-server-01 cat /etc/obs-agent/config.yaml

# View service logs
ssh your-server-01 sudo journalctl -u obs-agent -n 50
```

## Next Steps

1. Read `README.md` for complete documentation
2. Review `group_vars/obs_agents_production.yml` for production settings
3. Test on staging: `--limit obs_agents_staging`
4. Deploy to production with monitoring

---

**Need help?** See README.md for detailed documentation.
