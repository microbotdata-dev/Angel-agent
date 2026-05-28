# 🛡️ Angel Agent

> **Îngerul tău păzitor digital**  
> *Created by [MicroBot](https://microbot.uk) — Technology with a soul.*

**Your Personal Security Guardian — Open Source**

Angel is an AI-powered personal security agent that protects your digital identity. Not just an antivirus — it knows **what you have** to protect and watches those specific surfaces 24/7.

> *"BitDefender doesn't know you have a `.env` file in a repo you cloned 6 months ago. Angel does."*

## Features

| Feature | What it does | Cost |
|---------|-------------|------|
| 🔐 **Secret Scanner** | Finds API keys, passwords, tokens in plaintext files | Free |
| 🐙 **Git Secret Scanner** | Detects committed secrets in git history | Free |
| 🔍 **Credential Leak Check** | HIBP k-anonymity password check + Firefox Monitor | Free |
| 🌐 **Port Monitor** | Detects unexpected services listening on your machine | Free |
| ⚙️ **Process Monitor** | Flags unknown processes with high CPU or network | Free |
| 📁 **File Integrity** | Watches critical files for unauthorized changes | Free |
| 📢 **Discord Alerts** | Real-time CRITICAL/HIGH alerts + periodic summaries | Free |
| 🧠 **Self-Learning** | Gets smarter from your feedback — no coding needed | Free |

## Quick Start

### Install

```bash
# Clone
git clone https://github.com/YOUR_USER/angel-agent.git
cd angel-agent

# Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure
cp config/config.example.yaml ~/.angel/config.yaml
nano ~/.angel/config.yaml  # Add your email, Discord webhook, etc.

# Run once
python -m src.angel.core --once --config ~/.angel/config.yaml
```

### Requirements

- Python 3.9+
- macOS (Linux support planned)
- `lsof` (pre-installed on macOS)

## Configuration

All configuration is in `~/.angel/config.yaml`:

```yaml
# Who to protect
identities:
  emails:
    - "your@email.com"

# What to monitor
monitors:
  secrets:
    enabled: true
    paths:
      - "~/projects"
      - "~/.config"
  git_secrets:
    enabled: true
    repos:
      - "~/projects"
  ports:
    enabled: true
  processes:
    enabled: true
  file_integrity:
    enabled: true
    watch_paths:
      - "~/.ssh/authorized_keys"
      - "~/.env"
```

## How Learning Works

Angel improves without code changes:

1. Each alert has a unique ID
2. Run `angel --feedback <ID> always_ignore` for false positives
3. Angel remembers and never shows that alert again
4. Patterns are saved in `~/.angel/learned_rules.json`

```
Week 1: 50 alerts (15 false positives)
Week 4: 20 alerts (2 false positives) ← learning works!
Week 12: 5 alerts (all real threats)
```

## Architecture

```
┌──────────────────┐     ┌─────────────────┐
│   Hermes Agent   │◄────│   Angel Core     │
│ (optional client)│     │ (Python daemon)  │
└──────────────────┘     └────────┬─────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        ▼                         ▼                         ▼
┌──────────────┐   ┌──────────────────┐   ┌──────────────────┐
│  📡 Sensors  │   │  🧠 Learning     │   │  📢 Notifications│
│  · Secrets   │   │  · Suppression   │   │  · Discord       │
│  · Git       │   │  · Escalation    │   │  · Telegram      │
│  · Ports     │   │  · Known baselines│   │  · SMS (future) │
│  · Processes │   └──────────────────┘   └──────────────────┘
│  · Files     │
└──────────────┘
```

## Why Not Just Use BitDefender?

| Angel | BitDefender / Norton |
|-------|---------------------|
| Knows YOUR specific assets | Generic protection for "everyone" |
| Focuses on YOUR mistakes (plaintext secrets, git leaks) | Focuses on known malware signatures |
| Learns from YOUR feedback | Static rules |
| Open source, zero subscription | $40-120/year |
| Privacy-first (no cloud) | Telemetry to vendor cloud |
| Full control | Black box |

## Roadmap

- [x] Secret scanning (files)
- [x] Git secret detection
- [x] Port monitoring
- [x] Process monitoring
- [x] File integrity
- [x] Self-learning system
- [ ] KeePass/Bitwarden integration for password leak checks
- [ ] Pre-commit hook installer
- [ ] LuLu/Santa integration
- [ ] Human Safety Layer (real-time warnings)
- [ ] Web dashboard

## License

MIT
