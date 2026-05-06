# forensiq

DFIR intelligence platform for Windows forensic investigations. Parses triage collections, disk images, and memory dumps into a unified DuckDB case file, then provides an interactive web UI, REPL, detection engine, and IOC correlation.

## Features

- **Triage ZIP** — auto-routes artifacts: EVTX, Prefetch, AmCache, ShimCache, MFT, USN Journal, Registry hives, LNK, Jump Lists, Recycle Bin, ShellBags, Browser history (Chrome/Edge/Firefox, WAL-aware)
- **Disk images** — E01/EWF + raw; NTFS MFT + USN Journal extraction
- **Memory dumps** — pure-Go PAGEDUMP64 parser: processes, hidden process detection (DKOM), network connections with timestamps, modules, malfind, VAD scan
- **Web UI** — interactive investigation dashboard at `http://localhost:8080`
- **Detection engine** — 60+ built-in rules + SIGMA rule support + YARA-lite
- **IOC correlation** — import IP/hash/domain lists, cross-correlate against all artifacts
- **Timeline** — unified chronological view across all artifact sources
- **LLM integration** — Ollama-based artifact analysis (`forensiq ask`)

## Quick Start

### Install (Windows)

Download `forensiq.exe` from [Releases](../../releases) and run:

```
forensiq.exe analyze --triage collection.zip --case case.fcase
forensiq.exe serve --case case.fcase
```

Then open `http://localhost:8080` in your browser.

### Full analysis (triage + disk + RAM)

```
forensiq.exe analyze \
  --triage collection.zip \
  --disk disk.E01 \
  --ram memory.dmp \
  --case investigation.fcase

forensiq.exe serve --case investigation.fcase
```

### Interactive REPL

```
forensiq.exe repl --case investigation.fcase
```

## Build from Source

Requires Docker (cross-compiles to Windows .exe on any platform):

```bash
docker build -t forensiq-build -f Dockerfile.build .
docker run --rm -v $(pwd)/dist:/dist forensiq-build cp forensiq.exe /dist/
```

Or native Windows (requires Go 1.24+ and GCC/MinGW):

```
go build -o forensiq.exe .
```

## Commands

| Command | Description |
|---------|-------------|
| `analyze` | Parse artifacts into case file |
| `serve` | Launch web UI |
| `repl` | Interactive SQL/analysis shell |
| `detect` | Run detection rules |
| `hunt` | Threat hunting queries |
| `timeline` | Print unified timeline |
| `report` | Generate HTML report |
| `export` | Export tables to CSV/JSON |
| `yara` | YARA-lite scan |
| `ask` | LLM-assisted analysis (requires Ollama) |

## Supported Artifacts

| Category | Artifacts |
|----------|-----------|
| Execution | Prefetch, AmCache, ShimCache, UserAssist, BAM/DAM |
| Filesystem | MFT, USN Journal, LNK, Jump Lists, Recycle Bin, ShellBags |
| Registry | Run keys, Services, Scheduled Tasks, WMI subscriptions |
| Event Logs | Security, Sysmon, PowerShell, Defender, RDP, SMB |
| Browser | Chrome, Edge, Brave, Opera, Firefox (SQLite + WAL) |
| Memory | Processes, Network (with timestamps), Modules, Malfind |
| Linux | auth.log, shell history, wtmp, crontab, authorized_keys |

## Requirements

- Windows 10/11 x64 (target machine)
- Go 1.24+ (to build)
- Docker (for cross-compilation)
- Volatility3 in PATH (optional, for memory fallback)
- Ollama (optional, for `ask` command)
