# Competition readiness checklist

## Before the event

```bash
python3 -m ctf_agent health --no-demo
python3 -m ctf_agent playbooks --validate
python3 -m unittest discover -s tests -q
```

Review [AGENTS.md](../AGENTS.md), keep `provider=mock` until a provider is explicitly
approved, and prepare a disposable VM. Do not copy the personal/source SQLite state into
the competition workspace.

## Start a clean event workspace

```bash
mkdir -p .ctf-agent
python3 -m ctf_agent serve --host 127.0.0.1 --port 8765 \
  --db .ctf-agent/competition.db --no-demo
```

Use only exact challenge host/port entries supplied by the operator. Network is off by
default; enabling an allowlist does not authorize submission or a redirect.

## Per challenge

1. Preserve and hash the original file/PCAP/source.
2. Run deterministic triage and choose a playbook.
3. Keep raw binary/PCAP out of model context; pass bounded metadata/extractions.
4. Save `transcript.json`, `WRITEUP.md`, and an independent verifier beside the artifact.
5. Present `VERIFIED` candidates to the operator; never submit automatically.

## Parallel copy

The external path `/home/noppakorn/Desktop/CTF-Agent2` is the competition copy.  It has
the source/docs and filtered challenge workspace, plus a fresh `.ctf-agent/state.db`
(zero challenges and scopes).  Its own database and port keep the two projects from
mixing state.  If the copy must be recreated, use this filtered command:

```bash
rsync -a --exclude='.git/' --exclude='.ctf-agent/' --exclude='__pycache__/' \
  --exclude='*.pyc' --exclude='*.so' --exclude='*.bin' \
  --exclude='ctf_challenges/cryptohack_archive/solvers/tool_cache/' \
  /home/noppakorn/Desktop/CTF-Agent/ /home/noppakorn/Desktop/CTF-Agent2/
mkdir -p /home/noppakorn/Desktop/CTF-Agent2/.ctf-agent
```

```bash
cd /home/noppakorn/Desktop/CTF-Agent2
python3 -m ctf_agent health --db .ctf-agent/state.db --no-demo
python3 -m ctf_agent serve --host 127.0.0.1 --port 8766 \
  --db .ctf-agent/competition.db --no-demo
```

The source project’s existing database is intentionally preserved; it is not copied into
the clean competition database.

## Stop conditions

Pause a route after two failed prerequisites, three no-progress actions, budget/cap breach,
scope uncertainty, inconsistent parser output, or a candidate lacking independent replay.
