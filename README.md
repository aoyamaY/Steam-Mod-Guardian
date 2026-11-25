<p align="center"><img src="Guardian.App/Assets/AppIcon.png" width="96" alt="Steam Mod Guardian icon"></p>

# Steam Mod Guardian

**Offline-capable risk inspection for Steam Workshop and local game mods.**

[简体中文](README.zh-CN.md) · [Security](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)

![Windows](https://img.shields.io/badge/platform-Windows%20x64-0078D4) ![Version](https://img.shields.io/badge/version-2.1.0-blue) ![.NET](https://img.shields.io/badge/.NET-8-512BD4) ![License](https://img.shields.io/badge/license-MIT-green)

Steam Mod Guardian is an unofficial desktop tool that inspects mod files before you load them into a game. It supports locally discovered Steam libraries, selected games, and manually added mod directories. It reads files as data; it does not execute inspected assemblies or scripts. It is **not an antivirus, sandbox, or proof that a mod is safe**.

## Highlights

- Steam library detection, multi-game selection, Workshop titles and optional Chinese store names.
- SHA-256, signed community indicators, local domain/IP lists, persistent scan baselines and update checks.
- Managed IL inspection, bounded call-graph correlation, async state-machine links, script heuristics, PE imports and bounded embedded-payload/ZIP inspection.
- **New in 2.1.0:** bounded intraprocedural control-flow/taint analysis, constant string reconstruction, and SimHash similarity over normalized IL n-grams.
- Traditional YARA or optional YARA-X; Windows AMSI opt-in. Built-in rules are heuristic indicators, not a comprehensive malware signature database.
- Optional local capa, FLOSS and TLSH analysis for selected files; TCP/module observation and limited ETW event counts.
- Risk filters, evidence export, hash-verified quarantine/restore and pre-launch rechecks.

## Download and run (portable)

When a maintainer has published a release, download `SteamModGuardian-2.1.0-win-x64-portable.zip` and its `.sha256` from the repository's Releases page (or download the successful build artifact from Actions). Verify the ZIP checksum, extract the **entire** folder, and launch `Steam Mod Guardian.exe`. No installer, .NET Runtime installation, account or administrator access is required for ordinary static scanning. Do not move only the EXE. The self-contained build is Windows x64; other architectures are not currently packaged. Windows 11 is recommended for Acrylic appearance.

1. Refresh the Steam library or choose local mod folders under advanced settings.
2. Select games, then choose the recommended scan.
3. Review the red/high-risk, download and unknown categories. Inspect evidence before quarantining or unsubscribing.
4. Optional: configure additional engines; re-scan after mod updates.

## Detection engines and offline availability

| Technology | Local availability | Scope |
| --- | --- | --- |
| SHA-256, IL, call graph, PE, script and payload analysis | Built in | Heuristic/static, bounded file parsing |
| CFG and taint analysis | Built in | Selected IL sources/sinks, branches, local variables and operand stack; no complete interprocedural data flow |
| Constant propagation | Built in | Bounded string concatenation and Base64-derived host hints; no general deobfuscation |
| SimHash IL similarity | Built in | Cross-package near matches; capped comparison budget; not TLSH |
| YARA / YARA-X | Optional local CLI | Use one engine at a time; one-click setup for classic YARA requires Internet once; YARA-X is manually configured |
| capa / FLOSS / TLSH | Optional local CLI | Selected-file auxiliary analysis: capabilities, recovered host hints, TLSH digest and optional reference-file distance |
| AMSI | Optional Windows provider | Provider availability and cloud policy vary |
| TCP/modules / ETW | Local runtime observation | ETW requires elevation, aggregates selected-PID event names/counts for up to 60 s |
| VirusTotal / signed community sync / Steam title lookup | Online optional | Not required for local scanning |

### Optional tools

Obtain trusted Windows CLI binaries from the official projects: [YARA](https://github.com/VirusTotal/yara/releases), [YARA-X](https://github.com/VirusTotal/yara-x/releases), [capa](https://github.com/mandiant/capa/releases), [FLOSS](https://github.com/mandiant/flare-floss/releases), [TLSH](https://github.com/trendmicro/tlsh). Keep tools outside mod directories and verify their provenance. They are not bundled. Select **Configure YARA-X** to enable `yr.exe` using bundled rules, or select a scan result and **Local professional analysis** for capa/FLOSS/TLSH. The latter produces an independent report and does not change the main scan rating. These tools are not sandboxed; do not select mod executables as tools. The UI currently uses Simplified Chinese; documentation is bilingual.

## Risk policy and limitations

Direct file-download or suspected download-to-disk capabilities are deliberately rated critical, even if legitimate. Ordinary network requests alone are not automatically critical. Existing conservative co-occurrence rules remain in place; data-flow evidence is supplemental. A near match or YARA hit is not proof of malware. The scanner cannot reliably analyze arbitrary obfuscation, all async state machines, all native machine code or all scripting languages. Files exceeding limits may remain unknown. The app does not guarantee coverage of every mod file or every game loading mechanism. Pre-launch checks only govern launches initiated by this tool; Steam may change files after a check or restore quarantined files. Do not run suspected malware for testing.

## Privacy

Local static scanning does not upload samples. Steam title queries, YARA downloading, VirusTotal hash/domain lookup, and signed community updates are optional network operations. AMSI may use the configured provider's cloud protection/sample submission policy. Turn off online title lookup to avoid Steam title requests during scans. External analyzers are trusted third-party software, not network-isolated. Do not analyze untrusted files while the app is elevated for ETW. ETW briefly enables kernel providers; only event names and counts for the selected PID are retained by this feature. Do not post unredacted logs or reports publicly. Settings remain in `%LOCALAPPDATA%\DuckovModGuardian` for migration compatibility; the application files themselves are portable.

## Build from source

Requires Windows x64, .NET 8 SDK and NuGet connectivity for restore. From the repository root:

```powershell
.\build.bat
# Non-interactive build:
pwsh -File .\scripts\build-release.ps1
```

The script runs inert fixture tests, publishes a self-contained folder, copies rules/docs/notices, runs runtime and UI smoke tests, and writes a ZIP plus SHA-256 under `dist/`. On non-interactive Windows systems, the optional `-SkipUiSmoke` switch explicitly skips UI smoke testing; validate the result on a real desktop before release. The GitHub Actions workflow builds and uploads artifacts; maintainers must review the result and manually publish a Release. No published release is implied by this source archive. The 2.1.0 source was not compiled or runtime-verified in its authoring environment.

```text
Guardian.App/      WPF application, dialogs and optional runtime observer
Guardian.Core/     Static scanner, rules, local tools, cache and quarantine
Guardian.Tests/    Inert synthetic fixtures
rules/             Bundled heuristic YARA rules
scripts/           Portable release build
.github/           CI and issue templates
docs/              Technical details and historical notes
```

## License

MIT (project source; see [LICENSE](LICENSE)). Third-party components retain their own licenses: [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt). This project is not affiliated with Valve, Steam, or any game developer. The application icon is AI-generated; interface icons are Feather vectors.
