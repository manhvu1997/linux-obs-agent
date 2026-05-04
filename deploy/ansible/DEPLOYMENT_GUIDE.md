# obs-agent Ansible Deployment Guide

Complete guide for deploying obs-agent to multiple servers using production-grade Ansible playbooks.

## What You Have

A complete, production-ready Ansible role that:

✅ Deploys obs-agent binary to multiple servers  
✅ Generates configuration from variables (no manual config edits)  
✅ Manages systemd service lifecycle  
✅ Supports production, staging, and development environments  
✅ Enables/disables features via configuration  
✅ Includes comprehensive error handling  
✅ Provides dry-run capability  
✅ Supports rolling deployments  
✅ Follows Ansible best practices  

## Files Created

### Role Structure (in `roles/obs-agent/`)

```
defaults/main.yml          All variables with sensible defaults
tasks/
  ├── main.yml             Main deployment workflow
  └── binary_local.yml     Deploy from local build
handlers/main.yml          Service restart/reload handlers
templates/
  ├── config.yaml.j2       obs-agent configuration template
  ├── obs-agent.service.j2 systemd unit template
  └── obs-agent-logrotate.j2 Log rotation config
```

### Configuration Files

```
group_vars/
  ├── obs_agents.yml.example              Default (copy to obs_agents.yml)
  ├── obs_agents_production.yml          Production overrides
  ├── obs_agents_staging.yml             Staging overrides
  └── obs_agents_development.yml         Development overrides
host_vars/
  └── prod-server-01.yml.example         Per-host overrides
inventory/
  └── hosts.example                      Inventory template
```

### Playbooks & Configuration

```
site.yml              Main deployment playbook
ansible.cfg           Ansible runtime configuration
Makefile              Helper commands (deploy, test, verify)
requirements.txt      Python dependencies
```

### Documentation

```
README.md             Complete documentation (100+ lines)
QUICK_START.md        5-minute quick start guide
STRUCTURE.md          Directory structure & hierarchy
DEPLOYMENT_GUIDE.md   This file
```

## 30-Second Setup

```bash
# 1. Ensure binary exists
ls -la ../../build/obs-agent

# 2. Setup
cp group_vars/obs_agents.yml.example group_vars/obs_agents.yml
cp inventory/hosts.example inventory/hosts

# 3. Edit for your environment
vim inventory/hosts          # Add your servers
vim group_vars/obs_agents.yml  # Customize settings

# 4. Test
ansible all -i inventory/hosts -m ping

# 5. Deploy
ansible-playbook -i inventory/hosts site.yml
```

## Key Features

### 1. Variable-Based Configuration

Everything is configurable via variables. No hardcoded values:

```yaml
obs_agent:
  log_level: "info"              # Change log level
  metrics_addr: ":9200"          # Prometheus endpoint

obs_agent_trigger:
  cpu_usage_percent: 85.0        # Trigger CPU profile
  iowait_percent: 20.0           # Trigger IO analysis

obs_agent_mongo:
  enabled: true                  # Enable MongoDB tracing
  slow_query_threshold_ms: 1000  # Query latency threshold
```

### 2. Environment-Specific Overrides

Different settings for prod/staging/dev:

```
defaults (safe baseline)
    ↓
group_vars/obs_agents.yml (group defaults)
    ↓
group_vars/obs_agents_production.yml (production overrides)
    ↓
host_vars/hostname.yml (host-specific)
    ↓
CLI -e flags (highest priority)
```

### 3. Smart Deployment

```bash
# Dry-run before actual deployment
ansible-playbook -i inventory/hosts site.yml --check --diff

# Deploy only configuration (no binary change)
ansible-playbook -i inventory/hosts site.yml --tags config

# Deploy only service management
ansible-playbook -i inventory/hosts site.yml --tags service

# Rolling deployment (1 server at a time)
ansible-playbook -i inventory/hosts site.yml --serial 1

# Batch deployment (5 servers at a time)
ansible-playbook -i inventory/hosts site.yml --serial 5
```

### 4. Error Handling

- Validates kernel version (must be ≥ 5.4)
- Checks BTF availability
- Validates configuration YAML syntax
- Verifies systemd unit syntax
- Tests Prometheus metrics endpoint
- Confirms service startup

### 5. Handler-Based Restarts

Configuration changes automatically trigger service restart via handlers:

```yaml
- name: Deploy configuration
  template:
    src: "config.yaml.j2"
    dest: "/etc/obs-agent/config.yaml"
  notify: "restart obs-agent"  # Handler triggered only if changed
```

## Common Workflows

### Deploy to All Servers

```bash
# Dry-run
make deploy-check

# Deploy
make deploy
# or
ansible-playbook -i inventory/hosts site.yml
```

### Deploy to Production Only

```bash
# Dry-run
ansible-playbook -i inventory/hosts site.yml \
  --limit obs_agents_production --check --diff

# Deploy
make deploy-prod
# or
ansible-playbook -i inventory/hosts site.yml \
  --limit obs_agents_production
```

### Update Configuration Only

```bash
# Update config without changing binary
ansible-playbook -i inventory/hosts site.yml --tags config

# With custom values
ansible-playbook -i inventory/hosts site.yml --tags config \
  -e "obs_agent.log_level=debug" \
  -e "obs_agent_mongo.enabled=true"
```

### Deploy with Custom Settings

```bash
# From command line
ansible-playbook -i inventory/hosts site.yml \
  -e "obs_agent.log_level=debug" \
  -e "obs_agent_trigger.cpu_usage_percent=75.0"

# From JSON file
ansible-playbook -i inventory/hosts site.yml \
  -e @custom_vars.json
```

### Check Status

```bash
# Service status
make status
# or
ansible obs_agents -i inventory/hosts -m systemd -a "name=obs-agent"

# Verify metrics
make verify
# or
curl -s http://localhost:9200/metrics | head -20

# View logs
make logs
# or
ssh your-server sudo journalctl -u obs-agent -f
```

## Configuration Examples

### Production Servers (conservative)

`group_vars/obs_agents_production.yml`:
```yaml
obs_agent.log_level: "warn"          # Reduce noise
obs_agent_trigger.cpu_usage_percent: 90.0  # High threshold
obs_agent_limits.memory_max: "300M"  # More headroom
obs_agent_exporter.url: "https://central-collector.prod.example.com"
```

### Staging with Databases (testing)

`group_vars/obs_agents_staging.yml`:
```yaml
obs_agent.log_level: "info"
obs_agent_mongo.enabled: true
obs_agent_mongo.slow_query_threshold_ms: 1000
obs_agent_mysql.enabled: true
obs_agent_mysql.slow_query_threshold_ms: 500
```

### Development (debug mode)

`group_vars/obs_agents_development.yml`:
```yaml
obs_agent.log_level: "debug"         # Full debug output
obs_agent_trigger.cpu_usage_percent: 70.0  # Low threshold
obs_agent_fsync.slow_threshold_us: 500     # Catch all slowness
obs_agent_exporter.url: "http://localhost:8080"
```

## Inventory Structure

```ini
[obs_agents]
# All servers get default config from group_vars/obs_agents.yml
prod-01.example.com  ansible_host=10.0.1.10
staging-01.example.com  ansible_host=10.0.2.10

[obs_agents_production]
# These override with group_vars/obs_agents_production.yml
prod-01.example.com

[obs_agents_staging]
# These override with group_vars/obs_agents_staging.yml
staging-01.example.com
```

## Variables Reference

### Core Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `obs_agent.log_level` | string | info | Log level: debug, info, warn, error |
| `obs_agent.metrics_addr` | string | :9200 | Prometheus endpoint |
| `obs_agent_binary_source` | string | local | Binary source: local, remote_url, build |

### Trigger Thresholds

| Variable | Default | Activates Module |
|----------|---------|------------------|
| `obs_agent_trigger.cpu_usage_percent` | 85.0 | CPU profiler |
| `obs_agent_trigger.iowait_percent` | 20.0 | IO latency tracer |
| `obs_agent_trigger.load_normalised` | 1.5 | Runq latency |
| `obs_agent_trigger.ctx_switch_delta` | 100000 | Scheduler analysis |
| `obs_agent_trigger.net_error_delta` | 100 | TCP retransmit |

### Database Tracers

| Variable | Default | Purpose |
|----------|---------|---------|
| `obs_agent_mongo.enabled` | false | MongoDB query tracing |
| `obs_agent_mysql.enabled` | false | MySQL query tracing |
| `obs_agent_fsync.enabled` | true | fsync/fdatasync analysis |
| `obs_agent_writeback.enabled` | true | Memory pressure analysis |

See `roles/obs-agent/defaults/main.yml` for complete reference (200+ variables).

## Troubleshooting

### Check Syntax
```bash
make syntax
# or
ansible-playbook -i inventory/hosts site.yml --syntax-check
```

### Debug Mode
```bash
ansible-playbook -i inventory/hosts site.yml -vvv
```

### Verify Connectivity
```bash
make test
# or
ansible all -i inventory/hosts -m ping
```

### Check Generated Config
```bash
ssh prod-01 sudo cat /etc/obs-agent/config.yaml
```

### View Service Logs
```bash
ssh prod-01 sudo journalctl -u obs-agent -n 50 -f
```

### Rollback
```bash
# Binary automatically backed up
ssh prod-01 sudo ls -la /usr/local/bin/obs-agent*
ssh prod-01 sudo cp /usr/local/bin/obs-agent.backup /usr/local/bin/obs-agent
```

## Helper Commands

```bash
# Install dependencies
make install

# Syntax check
make syntax

# Lint (requires ansible-lint)
make lint

# Dry-run
make deploy-check

# Deploy to all
make deploy

# Deploy to production
make deploy-prod

# Deploy to staging
make deploy-staging

# Check status
make status

# Verify endpoints
make verify

# View logs
make logs

# Clean temporary files
make clean
```

## Next Steps

1. **Review the inventory**: `cat inventory/hosts.example`
2. **Customize variables**: `vim group_vars/obs_agents.yml`
3. **Test connectivity**: `make test`
4. **Dry-run deployment**: `make deploy-check`
5. **Deploy**: `make deploy`
6. **Verify**: `make status`

## Support

- **Complete guide**: See `README.md`
- **Quick start**: See `QUICK_START.md`
- **Structure**: See `STRUCTURE.md`
- **obs-agent docs**: See `../../CLAUDE.md`

## Advanced Topics

### Custom Binary Source
Change `obs_agent_binary_source` to:
- `remote_url` - Download from web
- `build` - Build on remote host

### Per-Host Customization
Create `host_vars/your-server.yml` for server-specific overrides.

### CI/CD Integration
```bash
# GitHub Actions, GitLab CI, etc.
ansible-playbook -i inventory/hosts site.yml \
  --limit $TARGET_ENV \
  -e "deployment_env=$CI_ENVIRONMENT_NAME"
```

### Monitoring Integration
Output includes metrics for Prometheus scraping:
```bash
curl http://localhost:9200/metrics
```

### Centralized Collection
Set exporter endpoint:
```yaml
obs_agent_exporter:
  url: "https://central-collector.example.com"
  batch_size: 1000
  flush_interval: "60s"
```

---

**Ready to deploy?** Start with `make test` to verify connectivity!
