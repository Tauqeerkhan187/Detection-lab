# Windows Detection Catalog

The Windows endpoint (Windows 11, Sysmon + Wazuh agent) is monitored with the
same philosophy as the Linux side: custom rules layer on top of Wazuh's built-in
Sysmon ruleset, adding ATT&CK-mapped severity where the built-ins are weak and
correlating across events they treat in isolation.

Rules live in [`../rules/windows_rules.xml`](../rules/windows_rules.xml).

---

## Telemetry

Sysmon (SwiftOnSecurity config) generates the endpoint telemetry; the Wazuh
agent ships the `Microsoft-Windows-Sysmon/Operational` channel to the manager
via an `eventchannel` localfile. The event IDs that matter here:

| Sysmon EID | Event | Used by |
|------------|-------|---------|
| 1 | Process creation | 100200 (PowerShell) |
| 13 | Registry value set | 100202 (persistence) |
| 22 | DNS query | 100201 (certutil ingress) |

---

## Rules

### 100200 — Obfuscated PowerShell
**Level 12** · T1059.001 Command and Scripting Interpreter: PowerShell · T1027 Obfuscated Files or Information

Fires on a process-creation event (EID 1) where `powershell.exe`/`pwsh.exe` runs
with hallmarks of obfuscation: `-EncodedCommand`, `-nop`, `-w hidden`,
`FromBase64String`, `-noni`. These flags are overwhelmingly associated with
malware delivery and rarely appear in legitimate interactive use. Fires
standalone — no competing built-in suppresses it.

### 100201 — certutil LOLBin ingress
**Level 12** · T1105 Ingress Tool Transfer · T1218 System Binary Proxy Execution

`certutil` downloading from a URL is a classic living-off-the-land technique.

The interesting part is *how* it's detected. The SwiftOnSecurity Sysmon config
does not log `certutil.exe` as a process-creation event (EID 1) — it trims that
binary from EID 1 to reduce noise. But it **does** capture certutil's outbound
DNS lookup as an EID 22 event. So this rule keys off the DNS event instead of
process creation.

That is a deliberate, sensor-aware choice: match the telemetry the config
actually emits, not the telemetry you assume exists. Writing the "obvious"
EID 1 rule first, watching it never fire, and tracing that back to a config
exclusion is documented in the findings below.

### 100202 — Registry Run-key persistence
**Level 12** · T1547.001 Boot or Logon Autostart Execution: Registry Run Keys

Fires when a value is written under a `CurrentVersion\Run` / `RunOnce` key —
the most common Windows persistence mechanism, and the direct analogue of the
honeypot's cron-persistence detection on the Linux side.

This rule **chains** off Wazuh's built-in rule 92302 (`reg.exe` modifying a Run
key), which is only level 6. Rather than re-matching the registry path,
100202 inherits 92302 via `<if_sid>` and escalates it to level 12 with an
ATT&CK mapping — the intended way to layer custom logic on the vendor ruleset.

### 100220 — Kill chain (correlation)
**Level 14** · T1105 + T1547.001 · ingress → persistence within 10 minutes

The highest-value Windows detection, and the mirror of the Linux kill-chain rule.

```xml
<rule id="100220" level="14" timeframe="600">
  <if_sid>100202</if_sid>              <!-- current event is persistence -->
  <if_matched_sid>100201</if_matched_sid>  <!-- ingress happened earlier -->
  <same_field>win.system.computer</same_field>
</rule>
```

In isolation, a certutil download and a registry Run-key write are two separate
level-12 alerts. When ingress is followed by persistence on the same host, this
rule fires a single level-14 alert carrying both techniques — describing a
compromise sequence rather than two disconnected events. It supersedes the
individual persistence alert rather than duplicating it.

---

## Severity model

Windows severities follow the same lifecycle logic as the Linux side:

| Level | Meaning | Rule |
|-------|---------|------|
| 12 | A significant single technique observed | 100200, 100201, 100202 |
| 14 | Correlated compromise sequence | 100220 |

Level 12+ lands in the dashboard's critical bucket, so persistence, ingress,
and the kill chain all surface immediately.

---

## Findings from testing

Building and testing these rules surfaced three issues that are worth recording,
because tracing each one from "the alert didn't fire" back to root cause is the
actual work of detection engineering.

### The SIEM detected the endpoint's antivirus detecting the test

While testing the certutil rule, a built-in rule fired repeatedly at **level 15**:
*"Executable file dropped in folder commonly used by malware."* On a freshly
installed Windows 11 VM, that warranted investigation.

Root cause: Windows Defender was identifying the test `certutil -urlcache`
command as `Trojan:Win32/Ceprolad.A` and quarantining it. Defender's quarantine
process writes an executable artifact into its own ProgramData folder — and
Sysmon logged *that* executable landing in a malware-associated path, which
tripped the level-15 rule.

So the alert chain was: test payload → Defender quarantines it → quarantine
artifact dropped → Sysmon logs the drop → SIEM alerts. The SIEM was detecting
the endpoint's AV reacting to the test. Correlating the Defender detection log
with the Sysmon-sourced SIEM alert to explain a single underlying event is a
core triage skill, and this was a clean live example of it.

The fix for continued testing was a scoped Defender exclusion folder
(`Add-MpPreference -ExclusionPath`) rather than disabling protection globally —
attacks execute inside the exclusion, telemetry is generated, and the rest of
the endpoint stays realistic. (Restored afterward.)

### A sensor config exclusion hid the expected event

The certutil ingress rule was first written against process creation (EID 1) and
never fired. Tracing the event through the manager's archive showed certutil
arriving only as an EID 22 (DNS) event — the Sysmon config excludes certutil
from EID 1 logging. The detection was rewritten to match the telemetry that
actually existed. Lesson: know what your sensor emits before writing rules
against it.

### Two Wazuh correlation quirks

- `frequency` must be greater than 1; `frequency="1"` is rejected and prevents
  the ruleset from loading. For a simple "A then B" chain, omit `frequency`
  entirely and keep only `timeframe`, so `if_matched_sid` requires a single
  prior match.
- `if_matched_sid` must reference a rule that actually fires. The kill-chain
  rule initially chained a built-in certutil rule that never triggered (because
  certutil produced no EID 1 event), so the correlation stayed silent until it
  was pointed at the custom ingress rule instead.

---

## Known gaps

- **Windows coverage is a focused set, not exhaustive.** Four custom rules on
  top of the built-in Sysmon ruleset, chosen for signal rather than breadth —
  the same lean approach as the Linux side.
- **Detections are tuned to the SwiftOnSecurity Sysmon config.** A different
  config (e.g. one that logs certutil at EID 1) would shift which event some
  rules key off.
- **No lateral-movement or credential-access rules yet.** LSASS-dumping and
  shadow-copy-deletion detections were scoped out of this pass; they're natural
  additions for a future iteration.
