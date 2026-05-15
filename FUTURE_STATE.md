# Future State

Ideas considered but not yet implemented.

## OT / ICS via Conpot

Add a Conpot container (`docker-compose.yml`) to give the lab an OT attack surface alongside the existing AD + LocalStack environments. Conpot speaks Modbus, S7Comm, IEC 60870-5-104, BACnet, SNMP and logs every protocol exchange — a forgiving starter target for learning ICS detection without risk of "breaking" a real process simulation.

**Starter Caldera adversary** (`ICS-Recon-Modbus-2026-Lab`):

| Ability | What it does | ATT&CK for ICS |
|---|---|---|
| `ot-01-discover` | `Test-NetConnection` sweep across :502, :102, :2404, :161, :47808 on the OT subnet | T0846 Remote System Discovery |
| `ot-02-modbus-id` | PowerShell + .NET TcpClient sending Modbus function 0x2B/0x0E ("Read Device Identification") to TCP:502 | T0888 Remote System Information Discovery |
| `ot-03-modbus-write` | Modbus function 0x05 ("Force Single Coil") — classic "attacker turned a pump off" telemetry | T0855 Unauthorized Command Message |

**Telemetry pipeline:** mount Conpot's `/var/log/conpot/` to a host volume, point Filebeat at it (same pattern as the CloudTrail flow), land it in `logs-conpot-*` in Elasticsearch. Detection rules then key on things like "Modbus 0x05 write from a Windows host outside the OT subnet."

**Tooling on Windows agents:** none initially — PowerShell + .NET `TcpClient` can speak Modbus natively. Add nmap to `install_win_tools.ps1` later for richer NSE enum (`modbus-discover`, `s7-info`).

**If we want more realism later:** swap Conpot for **GRFICSv2** (Fortiphyd Logic) — full chemical-plant simulation with separate HMI/PLC/engineering-workstation VMs and a physics model. Heavier (4 VMs, ~15 GB) but attacks have a real "did the process break" payoff.

## User-activity simulator on win11-victim

Generate believable benign noise (browsing Tranco top-1M subset, hitting a LocalStack-hosted Flask app, opening Office docs) so detection rules tuned on a quiet box don't false-positive in production. Build-your-own PowerShell loop is an afternoon; **GHOSTS NG** (CMU SEI) is the heavier purpose-built option.
