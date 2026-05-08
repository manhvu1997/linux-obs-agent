# obs-agent Ansible Deployment

Production-grade Ansible playbook for deploying the obs-agent (eBPF-powered Linux observability daemon) to multiple servers following Ansible best practices.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Project Structure](#project-structure)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Deployment](#deployment)
7. [Verification](#verification)
8. [Troubleshooting](#troubleshooting)
9. [Advanced Usage](#advanced-usage)
10. [Best Practices](#best-practices)

---

## Quick Start

```bash
# 1. Clone and navigate to the playbook directory
cd deploy/ansible

# 2. Build the obs-agent binary (or download from release)
make -C ../.. build

# 3. Create inventory from example
cp inventory/hosts.example inventory/hosts
# Edit inventory/hosts with your server IPs/hostnames

# 4. Create group variables
cp group_vars/obs_agents.yml.example group_vars/obs_agents.yml
# Edit to customize for your environment

# 5. Test connectivity
ansible all -i inventory/hosts -m ping

# 6. Deploy obs-agent
ansible-playbook -i inventory/hosts site.yml

# 7. Verify deployment
ansible obs_agents -i inventory/hosts -m uri -a "url=http://localhost:9200/metrics"
```

---

## Project Structure

```
deploy/ansible/
├── site.yml                          ← Main playbook (deploy to all hosts)
├── roles/
│   └── obs-agent/
│       ├── defaults/main.yml         ← Default variables (all config)
│       ├── tasks/
│       │   ├── main.yml              ← Main deployment tasks
│       │   └── binary_*.yml          ← Binary deployment strategies
│       ├── handlers/main.yml         ← Service reload/restart handlers
│       ├── templates/
│       │   ├── config.yaml.j2        ← obs-agent config template
│       │   ├── obs-agent.service.j2  ← systemd unit template
│       │   └── obs-agent-logrotate.j2 ← logrotate template
│       └── vars/main.yml             ← Role-specific variables
├── inventory/
│   ├── hosts.example                 ← Inventory template
│   └── hosts                         ← Actual inventory (created from example)
├── group_vars/
│   ├── obs_agents.yml.example        ← Default group variables
│   ├── obs_agents_production.yml    ← Production-specific overrides
│   ├── obs_agents_staging.yml       ← Staging-specific overrides
│   └── obs_agents_development.yml   ← Development-specific overrides
└── README.md                         ← This file
```

---

## Prerequisites

### Local (Control Node)
- Ansible ≥ 2.9 (recommend 2.10+)
- Python 3.6+
- `make` command (to build binary)
- Compiled `obs-agent` binary in `../../build/obs-agent`

### Remote (Managed Nodes)
- Linux kernel ≥ 5.4 with BTF enabled
- sudo/root access
- SSH access from control node
- systemd service manager
- Python 3 (for Ansible)

### System Requirements
```bash
# Ubuntu/Debian
sudo apt-get install -y \
    clang llvm libbpf-dev \
    linux-headers-$(uname -r) \
    bpftool

# RHEL/Fedora
sudo dnf install -y \
    clang llvm libbpf-devel \
    kernel-devel \
    bpftool
```

---

## Installation

### 1. Build obs-agent Binary

```bash
cd ../..
make build
# Binary will be at: build/obs-agent
```

### 2. Setup Ansible Environment

```bash
cd deploy/ansible

# Install dependencies (optional)
pip install -r requirements.txt  # If using a requirements file

# Create inventory from template
cp inventory/hosts.example inventory/hosts
```

### 3. Configure Inventory

Edit `inventory/hosts` with your server details:

```ini
[obs_agents]
prod-01.example.com  ansible_host=10.0.1.10   env=production
prod-02.example.com  ansible_host=10.0.1.11   env=production
staging-01.example.com ansible_host=10.0.2.10 env=staging

[obs_agents_production]
prod-01.example.com
prod-02.example.com

[obs_agents_staging]
staging-01.example.com
```

### 4. Configure Variables

```bash
# Copy example group variables
cp group_vars/obs_agents.yml.example group_vars/obs_agents.yml

# Customize for your environment
vi group_vars/obs_agents.yml
```

---

## Configuration

### All Configuration Via Variables

Every configuration option can be controlled via variables in:
- `group_vars/obs_agents.yml` - Default for all servers
- `group_vars/obs_agents_production.yml` - Override for production
- `group_vars/obs_agents_staging.yml` - Override for staging
- Command-line with `-e` flag

### Key Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `obs_agent_binary_source` | `local` | Binary source: `local`, `remote_url`, or `build` |
| `obs_agent.log_level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `obs_agent_trigger.cpu_usage_percent` | `85.0` | CPU threshold to activate CPU profiler |
| `obs_agent_mongo.enabled` | `false` | Enable MongoDB query tracing |
| `obs_agent_mysql.enabled` | `false` | Enable MySQL query tracing |
| `obs_agent_exporter.url` | `""` | Central server endpoint (empty = disabled) |

### Example Configurations

**Production (minimal, safe):**
```yaml
obs_agent:
  log_level: "warn"
obs_agent_trigger:
  cpu_usage_percent: 90.0
  iowait_percent: 30.0
obs_agent_limits:
  memory_max: "300M"
  cpu_quota: "15%"
```

**Staging (with database tracing):**
```yaml
obs_agent.log_level: "info"
obs_agent_mongo.enabled: true
obs_agent_mongo.slow_query_threshold_ms: 1000
```

**Development (debug mode):**
```yaml
obs_agent.log_level: "debug"
obs_agent_trigger.cpu_usage_percent: 70.0
obs_agent_fsync.slow_threshold_us: 500
```

---

## Deployment

### Basic Deployment

```bash
# Deploy to all hosts
ansible-playbook -i inventory/hosts site.yml

# Deploy to specific group
ansible-playbook -i inventory/hosts site.yml --limit obs_agents_production
```

### Targeted Deployments

```bash
# Deploy only installation tasks
ansible-playbook -i inventory/hosts site.yml --tags install

# Deploy only configuration (skip binary)
ansible-playbook -i inventory/hosts site.yml --tags config

# Deploy only service management
ansible-playbook -i inventory/hosts site.yml --tags service
```

### Override Variables via CLI

```bash
# Override log level
ansible-playbook -i inventory/hosts site.yml \
  -e "obs_agent.log_level=debug"

# Multiple overrides
ansible-playbook -i inventory/hosts site.yml \
  -e "obs_agent.log_level=debug" \
  -e "obs_agent_trigger.cpu_usage_percent=75.0" \
  -e "obs_agent_mongo.enabled=true"

# From JSON file
ansible-playbook -i inventory/hosts site.yml \
  -e @config_overrides.json
```

### Deployment Strategies

**Rolling deployment (one at a time):**
```bash
ansible-playbook -i inventory/hosts site.yml \
  --serial 1
```

**Batch deployment (5 servers at a time):**
```bash
ansible-playbook -i inventory/hosts site.yml \
  --serial 5
```

**Dry-run (check mode):**
```bash
ansible-playbook -i inventory/hosts site.yml \
  --check --diff
```

---

## Verification

### Verify Installation Success

```bash
# Check all obs-agent services are running
ansible obs_agents -i inventory/hosts -m systemd -a "name=obs-agent"

# Check metrics endpoint
ansible obs_agents -i inventory/hosts -m uri \
  -a "url=http://localhost:9200/metrics"

# Test diagnose API
ansible obs_agents -i inventory/hosts -m uri \
  -a "url=http://localhost:9200/api/diagnose"
```

### View Logs

```bash
# View on one host
ssh prod-01.example.com sudo journalctl -u obs-agent -f

# View on all hosts (requires 'ansible' package on control node)
ansible obs_agents -i inventory/hosts -m command \
  -a "journalctl -u obs-agent -n 20 --no-pager"
```

### Validate Configuration

```bash
# Check generated config
ssh prod-01.example.com sudo cat /etc/obs-agent/config.yaml

# Check systemd service
ssh prod-01.example.com sudo systemctl status obs-agent
```

---

## Troubleshooting

### Common Issues

**1. "kernel version is too old"**
```
Ensure Linux kernel ≥ 5.4 with BTF enabled:
  uname -r                    # Check kernel version
  cat /sys/kernel/btf/vmlinux # Check BTF availability
```

**2. "obs-agent binary not found"**
```
Build the binary first:
  make -C ../.. build
Or use remote_url source
```

**3. "Service fails to start"**
```
Check logs:
  sudo journalctl -u obs-agent -n 50
  
Common causes:
  - Missing capabilities: CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN
  - Config syntax error: validate with YAML parser
  - Port already in use: check netstat -tlnp | grep 9200
```

**4. "Permission denied accessing /sys/fs/bpf"**
```
The service requires specific capabilities. Ensure:
  - User is obs-agent (created by playbook)
  - systemd unit has correct AmbientCapabilities
  - SELinux is not blocking (if applicable)
```

### Debug Mode

```bash
# Run playbook with verbose output
ansible-playbook -i inventory/hosts site.yml -vvv

# Enable debug logging in obs-agent
ansible-playbook -i inventory/hosts site.yml \
  -e "obs_agent.log_level=debug"

# Check Ansible facts
ansible obs_agents -i inventory/hosts -m setup | head -50
```

### Rollback

```bash
# Stop service
ansible obs_agents -i inventory/hosts -m systemd \
  -a "name=obs-agent state=stopped"

# Restore from backup
ansible obs_agents -i inventory/hosts -m copy \
  -a "src=/etc/obs-agent/config.yaml.backup dest=/etc/obs-agent/config.yaml"

# Restart
ansible obs_agents -i inventory/hosts -m systemd \
  -a "name=obs-agent state=started"
```

---

## Advanced Usage

### Custom Binary Sources

**Option 1: Remote URL**
```yaml
# In group_vars/obs_agents.yml
obs_agent_binary_source: "remote_url"
obs_agent_binary_url: "https://releases.example.com/obs-agent-v1.0.0"
```

**Option 2: Build on-the-fly**
```yaml
obs_agent_binary_source: "build"
obs_agent_build_path: "/path/to/repo"
```

### Environment-Specific Deployments

```bash
# Deploy with environment-specific variables
ansible-playbook -i inventory/hosts site.yml \
  --limit obs_agents_production \
  -e "deployment_env=production"

# Production with stricter settings
ansible-playbook -i inventory/hosts site.yml \
  --limit obs_agents_production \
  -e "obs_agent_limits.memory_max=100M" \
  -e "obs_agent_limits.cpu_quota=5%"
```

### Database-Specific Deployments

```bash
# Enable MongoDB tracing on MongoDB servers
ansible-playbook -i inventory/hosts site.yml \
  --limit mongo_servers \
  -e "obs_agent_mongo.enabled=true" \
  -e "obs_agent_mongo.slow_query_threshold_ms=500"

# Enable MySQL tracing on MySQL servers
ansible-playbook -i inventory/hosts site.yml \
  --limit mysql_servers \
  -e "obs_agent_mysql.enabled=true"
```

### Custom Handlers

Add to `roles/obs-agent/handlers/main.yml`:

```yaml
- name: send deployment notification
  slack:
    token: "{{ slack_token }}"
    channel: "#deployments"
    msg: "obs-agent deployed on {{ inventory_hostname }}"
  when: notify_slack
```

---

## Best Practices

### 1. Test Before Production

```bash
# Test on staging first
ansible-playbook -i inventory/hosts site.yml \
  --limit obs_agents_staging \
  --check --diff

# Then deploy to production
ansible-playbook -i inventory/hosts site.yml \
  --limit obs_agents_production
```

### 2. Use Variable Hierarchy

```
Precedence (highest to lowest):
  1. CLI arguments (-e flag)
  2. Host variables (inventory/hosts)
  3. Group variables (group_vars/*)
  4. Role defaults (roles/*/defaults/main.yml)
```

### 3. Consistent Naming

- Variable names match config.yaml keys: `obs_agent_fsync`, `obs_agent_mongo`
- Use descriptive host names in inventory
- Tag tasks for granular control

### 4. Idempotent Deployments

- All tasks are idempotent (safe to re-run)
- Config changes trigger handlers (safe restart)
- Binary changes detected and applied

### 5. Monitoring Deployments

```bash
# Monitor during deployment
watch -n 1 'ansible obs_agents -i inventory/hosts -m systemd -a "name=obs-agent" 2>/dev/null'

# Check metrics collection
ansible obs_agents -i inventory/hosts -m uri -a "url=http://localhost:9200/metrics" --one-line
```

### 6. Documentation

- Document all custom variables in `group_vars/`
- Use `.yml.example` files as templates
- Keep inventory comments updated
- Document environment-specific decisions

### 7. Version Control

```bash
# Track changes to configs
git add -A
git commit -m "obs-agent: update config for prod"

# Review diffs before deployment
git diff
```

---

## Advanced Tag-Based Workflows

```bash
# Install only (no config/service changes)
ansible-playbook -i inventory/hosts site.yml --tags install

# Config only (no binary changes)
ansible-playbook -i inventory/hosts site.yml --tags config

# Service management only
ansible-playbook -i inventory/hosts site.yml --tags service

# Validation only
ansible-playbook -i inventory/hosts site.yml --tags validate

# Multiple tags
ansible-playbook -i inventory/hosts site.yml --tags install,config
```

---

## Support

For issues with the Ansible playbook:
1. Check Troubleshooting section above
2. Run with `-vvv` for full debug output
3. Verify prerequisites are met
4. Check inventory syntax: `ansible-inventory -i inventory/hosts --graph`

For obs-agent issues:
- See obs-agent documentation: `../../CLAUDE.md`
- Check service logs: `journalctl -u obs-agent -f`
- Review config: `cat /etc/obs-agent/config.yaml`
