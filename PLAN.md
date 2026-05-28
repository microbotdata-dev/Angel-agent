# Angel — Plan Arhitectural Agent de Securitate

> **Versiune:** 1.0 | **Data:** 28 Mai 2026
> **Scop:** Agent AI autonom "Îngerul Păzitor" — protejează pe Cristi de toate pericolele online

---

## 1. Arhitectura Generala

```
┌────────────────────────────────────────────────────────────────────┐
│                        ANGEL ORCHESTRATOR                          │
│              (Hermes Skill: angel-agent / Python cron)              │
│                                                                    │
│  ┌─────────────┐  ┌────────────┐  ┌──────────┐  ┌──────────────┐  │
│  │ Monitor     │  │ Investigate│  │Respond   │  │ Train/Learn  │  │
│  │ (detecteaza)│→│ (analizeaza)│→│(remediaza)│  │ (imbunatateste)│  │
│  └──────┬──────┘  └─────┬──────┘  └────┬─────┘  └──────┬───────┘  │
│         │               │              │               │          │
└─────────┼───────────────┼──────────────┼───────────────┼──────────┘
          │               │              │               │
          ▼               ▼              ▼               ▼
┌────────────────────────────────────────────────────────────────────┐
│                        STRATUL DE SENZORI                          │
├────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  🔐 CREDENTIALS              🔍 SCANNING          🛡️ FIREWALL     │
│  ┌──────────────────┐  ┌────────────────────┐  ┌──────────────────┐│
│  │ HIBP API         │  │ YARA-X + YARA rules│  │ LuLu (outbound)  ││
│  │ Firefox Monitor │  │ Gitleaks (git)     │  │ pf (inbound)     ││
│  │ Sherlock (users) │  │ TruffleHog (depth) │  │ AdGuard Home DNS ││
│  │ KeePass audit    │  │ Malware-pre-scan   │  │ NEXTdns fallback ││
│  └──────────────────┘  └────────────────────┘  └──────────────────┘│
│                                                                     │
│  📊 SYSTEM MONITORING      👁️ PRIVACY            🧠 THREAT INTEL  │
│  ┌──────────────────┐  ┌────────────────────┐  ┌──────────────────┐│
│  │ osquery (state)  │  │ Oversight (cam/mic)│  │ AlienVault OTX   ││
│  │ Santa (exec)     │  │ ReiKey (keyboard)  │  │ CIRCL MISP feeds ││
│  │ BlockBlock(pers) │  │ TCC db watcher     │  │ Abuse.ch URLhaus ││
│  │ RansomWhere?     │  │                    │  │ VirusTotal API   ││
│  └──────────────────┘  └────────────────────┘  └──────────────────┘│
│                                                                     │
│  🐙 CODE INTEGRITY         💾 BACKUP             🌐 NETWORK        │
│  ┌──────────────────┐  ┌────────────────────┐  ┌──────────────────┐│
│  │ Git pre-commit    │  │ Automated backup   │  │ Port scan detect ││
│  │ hooks (Gitleaks) │  │ Encryption AES-256  │  │ C2 conn detect   ││
│  │ Docker scan      │  │ Cloud upload (rclone)│ │ Beaconing detect ││
│  │ Repo audit       │  │ Disaster recovery   │  │ DNS anomaly      ││
│  └──────────────────┘  └────────────────────┘  └──────────────────┘│
└────────────────────────────────────────────────────────────────────┘
```

### Flux Principal de Operare

```
1. MONITOR → senzorii emit evenimente JSON
2. CORRELATE → Angel combine semne (ex: port nou + proces necunoscut)
3. SCORE → calculeaza threat level (LOW/MEDIUM/HIGH/CRITICAL)
4. DECIDE → match pe playbook (izolare, kill, notificare, ignorare)
5. ACT → executa actiunea + logheaza
6. VERIFY → reconfirma ca amenintarea e rezolvata
7. LEARN → actualizeaza reguli/baseline pe baza outcome-ului
```

### Delivery: Unde ajung alertele

| Threat Level | Canal | Format |
|---|---|---|
| CRITICAL | Discord #angel-alerts + SMS | 🔴 Atac activ detectat! |
| HIGH | Discord #angel-alerts | 🟠 Amenintare serioasa — actiune necesara |
| MEDIUM | Discord #angel-report (daily digest) | 🟡 Atentie — investigat |
| LOW | Discord #angel-report (weekly) | 🔵 Informatii |

---

## 2. Faza 1: Fundatia (Acum — 7 zile)

### Obiectiv: Angel devine orchestrator peste ce avem deja

### 2.1 Script Principal — `angel-agent.sh` / `angel_agent.py`

**Cale:** `~/cosmos/scripts/angel/angel_agent.py`
**Cron:** La fiecare 30 minute (monitor) + la incident (trigger)

Ce face in Faza 1:

```python
# ~/cosmos/scripts/angel/angel_agent.py (skeleton)
# Orchestrator principal Angel

PHASES = {
    "monitor": {
        "check_credential_leaks": call_HIBP_API(),
        "check_daily_audit": parse_latest_audit_log(),
        "check_open_ports": compare_ports_vs_baseline(),
        "check_suspicious_processes": analyze_process_list(),
        "check_git_secrets": run_gitleaks_on_repos(),
        "check_dns_blocking": verify_adguard_active(),
    },
    "investigate": {
        "correlate_findings": combine_signals(),
        "score_threat": calculate_risk_score(),
        "match_playbook": choose_response(),
    },
    "respond": {
        "notify_cristi": send_discord_alert(),
        "auto_remediate": execute_playbook(),
        "verify_fix": reconfirm_safety(),
    },
    "learn": {
        "update_baseline": adjust_normal_behavior(),
        "log_incident": save_to_incident_db(),
        "update_rules": refine_detection(),
    }
}
```

### 2.2 Credential Leak Monitor (Prima Prioritate)

**Problema pe care ai mentionat-o:** parole expuse in clar.

**Actiuni imediate:**

1. **HIBP API Setup** — inregistreaza Cristi (toate emailurile) pentru breach monitoring
   - Emailuri: mihailaionutcristian@gmail.com, microbot.data@gmail.com
   - API: HIBP v3 (free tier, ~$3.50/luna pentru Pro)
   - Script: `~/cosmos/scripts/angel/check_hibp.py` — ruleaza la fiecare 6h

2. **Scanare parole in clar pe sistem**
   ```bash
   # Cauta fisiere care contin pattern-uri de parole/chei
   find ~ -maxdepth 4 -name ".env" -o -name "*.env" 2>/dev/null
   find ~ -maxdepth 3 -name "*.kdbx" -o -name "*.key" 2>/dev/null
   # Verifica permisiuni .env
   ls -la ~/.hermes/.env ~/cosmos/.env ~/cosmos/projects/*/.env 2>/dev/null
   ```

3. **Sherlock scan** — verifica username-uri pe site-uri compromise
   - Username-uri: mihailaionutcristian, cristim77, microbot
   - Script: `~/cosmos/scripts/angel/check_sherlock.sh`

4. **Gitleaks pe toate repo-urile locale**
   ```bash
   for repo in ~/cosmos/projects/*/; do
     gitleaks detect --source "$repo" --report-format json --report-path /tmp/gitleaks_report.json
   done
   ```

5. **Verificare KeePass** — audit credentiale (parole slabe, duplicate, expirate)
   - Script: `~/cosmos/scripts/angel/audit_keepass.py`

### 2.3 Integrare Tool-uri Existente

| Tool Existent | Cum il integreaza Angel | Frecventa |
|---|---|---|
| `cosmos_daily_audit.py` | Parseaza output-ul JSON, extrage findings HIGH/CRITICAL | Zilnic |
| `malware-pre-scan` | Ruleaza automat la orice `git clone` / cod tert | La eveniment |
| `izolare` | Playbook de response: detectie atac → trigger izolare | La incident |
| `security-remediation` | Playbook-uri standard pentru fiecare tip de incident | La incident |
| `security-credential-manager` | Rotire automata parole la breach detectat | La incident |

### 2.4 Delivery Pipeline

1. Creeaza canal Discord `#angel-alerts`
2. Angel posteaza automat:
   - 🔴 Alerte critice in `#angel-alerts` (imediat)
   - 📊 Raport zilnic in `#angel-report` (09:00)
   - 📈 Raport saptamanal in `#angel-report` (Luni 09:00)

### 2.5 Fisiere de Creat (Faza 1)

```
~/cosmos/scripts/angel/
├── angel_agent.py          # Orchestrator principal
├── check_hibp.py           # HIBP API credential check
├── check_sherlock.sh       # Username exposure check
├── audit_keepass.py        # KeePass password audit
├── scan_env_files.py       # Find plaintext secrets in files
├── playbooks/
│   ├── credential_leak.md  # Ce faci cand o parola e leak-uita
│   ├── port_exposed.md     # Ce faci cand un port apare pe 0.0.0.0
│   ├── suspicious_process.md
│   └── active_attack.md    # Activeaza izolare
├── config.yaml             # Configuratie Angel
└── README.md               # Documentatie
```

---

## 3. Faza 2: Extindere (7-30 zile)

### 3.1 Tool-uri Noi de Instalat

| Tool | Comanda | Rol | Memorie |
|---|---|---|---|
| **YARA-X** | `brew install yara-x` | Scanner malware modern (inlocuieste ClamAV) | ~30MB |
| **LuLu** | Download de pe objective-see.org | Outbound firewall + logging | ~30MB |
| **Santa** | `brew install santa` | Binary authorization (whitelist/blacklist) | ~40MB |
| **BlockBlock** | Download de pe objective-see.org | Persistence monitoring (plist-uri noi) | ~20MB |
| **Oversight** | Download de pe objective-see.org | Camera/mic monitoring | ~10MB |
| **ReiKey** | Download de pe objective-see.org | Keylogger detection | ~5MB |
| **Gitleaks** | `brew install gitleaks` | Secret scanning in git | ~20MB |
| **TruffleHog** | `brew install trufflehog` | Deep secret scanning cu verificare | ~30MB |
| **AdGuard Home** | `brew install adguardhome` | DNS-based threat blocking | ~60MB |
| **osquery** | `brew install osquery` | System state query engine | ~30MB |
| **RansomWhere?** | Download objective-see.org | Ransomware behavioral detection | ~15MB |

**Total memorie noua:** ~290MB la activ, ~150MB idle.

### 3.2 Automatizari Noi

1. **GitLeaks pre-commit hook** — pe toate repo-urile
   ```bash
   # Instalare globala
   gitleaks install --global
   # In fiecare repo
   for repo in ~/cosmos/projects/*/; do
     cd "$repo" && [ -d .git ] && pre-commit install 2>/dev/null || true
   done
   ```

2. **AdGuard Home config** — DNS blocking automat
   - Block lists: OISD big, StevenBlack, NoCoin, Phishing Army
   - Update automat: cron zilnic
   - Angel API: `curl http://localhost:3000/control/filtering/status`

3. **LuLu + pf integration**
   - LuLu: block all unknown outbound (whitelist mode)
   - pf anchors: Angel scrie reguli dinamice (blocheaza IP-uri C2)
   - Script: `~/cosmos/scripts/angel/pf_block.sh <IP>`

4. **osquery schedule** — query-uri periodice
   ```sql
   -- Procese cu listening socket (la fiecare 5 min)
   SELECT p.name, p.pid, l.port, l.address
   FROM processes p JOIN listening_ports l ON p.pid = l.pid
   WHERE l.address = '0.0.0.0';
   
   -- Launchd plist-uri noi (la fiecare 10 min)
   SELECT * FROM launchd WHERE name NOT IN (baseline);
   ```

### 3.3 Playbook-uri Automate

| Trigger | Actiune automata | Notificare |
|---|---|---|
| Parola leak-uita in HIBP | Roteste parola in KeePass + update .env + notifica | 🔴 Discord |
| Port nou pe 0.0.0.0 | Investigheaza procesul, daca necunoscut → opreste | 🟠 Discord |
| Fisier .env cu permisiuni 644 | Schimba in 600, alerteaza | 🟡 Discord |
| Proces CPU >90% sustained | Kill + salveaza snapshot proces | 🟠 Discord |
| Conexiune C2 detectata | Blocheaza IP in pf + activeaza izolare | 🔴 SMS |
| Plist nou in LaunchAgents | Verifica signatura, flag daca unsigned | 🟡 Discord |

---

## 4. Faza 3: Intelligence (30-90 zile)

### 4.1 ML Anomaly Detection

**Approach:** Baseline + outlier scoring local (CoreML)

1. **Colectare baseline 7 zile:**
   - Procese normale (lista, CPU, memorie, retea)
   - Conexiuni normale (IP-uri, porturi, frecventa)
   - Porturi deschise normale
   - Fisiere modificate normal

2. **Detectie anomalii:**
   - Proces nou care nu e in baseline
   - Conexiune catre IP neverificat
   - Port deschis in afara orelor normale
   - Comportament de beaconing (conexiuni periodice)

3. **Local inference** cu Ollama (Gemma 4):
   ```python
   # Analiza contextuala a alertelor
   prompt = f"""Analizeaza aceste alerte combinate:
   - Port nou: {port} (proces: {process})
   - Conexiune catre: {ip}
   - Proces CPU: {cpu}%
   
   Este aceasta o amenintare reala sau fals pozitiv?
   Ce recomanzi?
   """
   ```

### 4.2 Threat Intelligence Feeds

| Feed | URL | Update | Cost |
|---|---|---|---|
| AlienVault OTX | `https://otx.alienvault.com/api/v1/` | 1h | Free |
| CIRCL MISP | `https://www.circl.lu/` | 6h | Free |
| URLhaus | `https://urlhaus.abuse.ch/downloads/` | 1h | Free |
| PhishTank | `http://data.phishtank.com/data/` | 6h | Free |
| Feodo Tracker | `https://feodotracker.abuse.ch/` | 1h | Free |

### 4.3 Dashboard Web

**Optiuni:**
1. **Grafana** — full dashboard, multe optiuni, dar mai greu
2. **Web UI simplu** — HTML/JS, API call-uri catre Angel
3. **Discord ca dashboard** — canale dedicate cu rapoarte

**Recomandare:** Incepe cu Discord, treci la Grafana in Faza 3.

---

## 5. Faza 4: Maturitate (90-180 zile)

### 5.1 Self-Healing

- Auto-rotation parole la breach detectat (prin KeePass API)
- Auto-restore config din backup la coruptie detectata
- Auto-repair permisiuni fisiere
- Auto-update tool-uri de securitate

### 5.2 Dark Web Monitoring

- Tor + custom crawler pentru paste-uri si forumuri
- IntelX API pentru cautari automate
- LeakCheck API pentru verificari suplimentare

### 5.3 Advanced Threat Intel

- OpenCTI deployment (Docker, port 8082)
- MITRE ATT&CK mapping pentru fiecare alerta
- Threat scoring cu context istoric

---

## 6. Metrici si Monitoring

### KPI-uri Principale

| Metric | Target | Masura |
|---|---|---|
| Time to detect | < 30 min de la aparitie | Log timestamp |
| Time to respond | < 5 min pentru CRITICAL | Playbook execution time |
| False positive rate | < 20% | Alerts / false alerts |
| Credential check coverage | 100% din credentiale | Toate cheile in KeePass |
| Tool availability | > 99% | Uptime monitor |
| Password leak detection | < 1h de la breach public | HIBP poll time |

### Rapoarte

**Zilnic (09:00):**
```
🛡️ Angel Report — 28 Mai 2026
─────────────────────────────
✅ Credential check: 0 breach-uri noi
✅ Port scan: 0 porturi neasteptate
✅ Process audit: 0 anomalii
✅ File integrity: 0 fisiere modificate
✅ DNS blocking: 127 blocari azi
✅ Git secret scan: 0 secrete expuse

📊 Threat level: LOW (scor 1.2/10)
🕐 Ultima alerta: Acum 12h (HIGH — port 8888)
```

**Saptamanal (Luni):**
```
📈 Angel Weekly — 24-30 Mai 2026
Total alerte: 12 (0 CRITICAL, 2 HIGH, 4 MED, 6 LOW)
Timp mediu raspuns: 47s
Falsi pozitivi: 3 (25%)
Top amenintari: Port scanning, Phishing emails
Tool-uri active: 8/10 (AdGuard DOWN 2h Luni)
```

---

## 7. Cost si Resurse

### Memorie RAM Estimata (cand totul e activ)

| Componenta | RAM | Note |
|---|---|---|
| Angel orchestrator (Python) | ~50MB | Idle, creste la alerta |
| YARA-X (daemon) | ~30MB | Doar la scan |
| LuLu (sysx) | ~30MB | Background constant |
| Santa (sysx) | ~40MB | Background constant |
| BlockBlock (sysx) | ~20MB | Background constant |
| Oversight (sysx) | ~10MB | Background constant |
| AdGuard Home | ~60MB | Background constant |
| osqueryd | ~30MB | Background constant |
| Ollama (Gemma 4) | ~200MB | Doar la analiza |
| **Total activ** | **~470MB** | |
| **Total idle** | **~240MB** | Fara Ollama + YARA |

Pe Mac Mini M4 cu 24GB RAM: ~2% din RAM in idle, ~4% activ. Zero impact.

### Costuri Lunare

| Serviciu | Cost | Necesar |
|---|---|---|
| HIBP Pro API | ~$3.50/mo | Pentru breach monitoring |
| VirusTotal API | Free | 500 calls/zi |
| AlienVault OTX | Free | Ilimitati |
| IntelX | Free | 50 queries/zi |
| NextDNS | Free | 300k queries/luna |
| **Total** | **~$3.50/mo** | |

Fata de BitDefender ($40/an), Norton ($60/an), SentinelOne ($120/an) — Angel e **free** daca ignori HIBP Pro.

### Timp de Implementare

| Faza | Timp | Efort |
|---|---|---|
| Faza 1 (Fundatia) | ~7 zile | 4-6h |
| Faza 2 (Extindere) | ~23 zile | 8-12h |
| Faza 3 (Intelligence) | ~60 zile | 16-24h |
| Faza 4 (Maturitate) | ~90 zile | 24-40h |

---

## 8. Riscuri si Mitigari

| Riscul | Impact | Probabilitate | Mitigare |
|---|---|---|---|
| Fals pozitiv oboseste utilizatorul | MED | RIDICATA | Tune thresholds, canal separat pentru CRITICAL |
| Tool X se opreste si nu stim | MED | MEDIE | Health check in fiecare ciclu Angel |
| Angel insusi e compromis | CRITICAL | SCĂZUTĂ | Ruleaza cu permisiuni minime, fara root |
| API key HIBP expira | SCĂZUT | MEDIE | Monitoring cu reminder inainte de expirare |
| macOS update sparge tool-urile | MED | MEDIE | Testare pe versiuni beta, backup config |
| Consum excesiv CPU la scanari | SCĂZUT | SCĂZUTĂ | Programare scanari in idle time (noaptea) |
| Over-alerting duce la ignorare | MED | RIDICATA | Smart scoring, agregare alerte similare |

### Decizii Arhitecturale Cheie

1. **Python, nu bash** — logica complexa, JSON parsing, API calls
2. **Launchd, nu PM2** — serviciile de securitate trebuie sa mearga independent
3. **Evenimente JSON, nu syslog** — mai usor de procesat programatic
4. **Discord ca UI primar** — deja folosit, notificari in timp real
5. **Ollama local, nu API extern** — confidentialitate, zero cost
6. **Baseline dinamic** — Angel invata ce e normal, nu reguli statice

---

## 9. Next Steps (Ce Facem Maine)

1. **Aproba planul** — Cristi verifica si zice OK sau modifica
2. **Creeaza structura Angel** (`~/cosmos/scripts/angel/`)
3. **Scrie `angel_agent.py`** — orchestratorul principal (faza 1)
4. **Configureaza HIBP API** — primul senzor activ
5. **Ruleaza Gitleaks pe toate repo-urile** — scanare initiala
6. **Creeaza canal `#angel-alerts`**
7. **Primul test: "Angel, verifica-ma"** — Cristi vede daca functioneaza

---

*"Nu doar antivirus — ingerul tau pazitor digital."*
