# Companion App (Satellite Git + Ansible Orchestrator)

Isolated companion project for managing satellite host sync and Ansible execution patterns for this repo.

## What It Does (MVP)
- Stores satellite host definitions and automation profile templates
- Prepares a local automation repo cache path (GitOps style)
- Renders an Ansible inventory + vars bundle from templates
- Builds a safe `ansible-playbook` command (dry-run by default)
- Records run metadata/log placeholders under `runtime/`

This scaffold is intentionally isolated so it does not collide with the main app's `output/` artifacts.

## Isolation Rules
- All generated artifacts go to `companion-app/runtime/`
- Config examples live in `companion-app/config/`
- Templates live in `companion-app/templates/`
- No writes to the main app `output/` directory

## Quick Start
```powershell
cd companion-app
python -m app.cli init
python -m app.cli render --hosts config/hosts.example.json --profile config/profile.cve-radar.example.json
python -m app.cli plan-run --hosts config/hosts.example.json --profile config/profile.cve-radar.example.json
```

## Commands
- `init`: creates runtime paths and a local state file
- `render`: renders inventory/vars for a selected host set/profile into `runtime/generated/<timestamp>/`
- `plan-run`: prints the exact Git sync + `ansible-playbook` command that would run
- `sync-repo`: updates or clones the automation repo cache (optional execution)

## Intended Pattern for This Repo
Use profile `cve-radar-satellite` to deploy/update the AI CVE Watcher on satellite hosts via Ansible:
- sync automation Git repo
- install/update Python deps
- place env file
- restart `cve_agent` service/process
- health check `/api/poll/status`

## Notes
- The scaffold is CLI-first for speed and cleanliness.
- Runtime execution is opt-in (`--execute`) and defaults to dry-run/plan output.
- Secrets should be passed via environment variables or vaulted Ansible vars, not committed JSON.
