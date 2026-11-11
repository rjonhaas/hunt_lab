# War Wagon — workshop guide

[Repository home](../../README.md) · [Evidence worksheet](hunt-worksheet.md)

## 1. Install or join the hosted lab

**Hosted:** open the Kibana URL supplied by the instructors. You do not install
VMs or log into Caldera. The instructor demonstrates and runs the shared operation.

**Local:** follow [local setup](../../docs/local-setup.md) before class. It builds
the four VMs, installs the endpoint tools, enables the required Sysmon file rule,
and preloads the workshop abilities and adversary. It does not run an attack.
If instructors supplied a conference configuration, install it as directed
before setup; otherwise you get the public practice exercise.

After setup, check readiness from the repository folder:

```text
vagrant ssh docker-host -c 'python3 /vagrant/scripts/validate_lab.py'
```

Resolve failed checks before proceeding. Fresh builds take hours, not minutes.

## 2. Find the URLs and logins

**Local:** open `lab-info.md` in your cloned folder after setup succeeds:

```bash
# Linux
cat lab-info.md
```

```powershell
# Windows PowerShell
Get-Content .\lab-info.md
```

It lists Kibana, Caldera, VM addresses and domain logins. The generated file is
local to your machine and is not on GitHub. If setup failed before creating it,
fix the reported stage first. See [access details](../../docs/local-setup.md#accessing-the-lab).

**Hosted:** use the instructor-provided Kibana URL and learner account. Local
`192.168.56.*` URLs and local administrator credentials do not apply.

## 3. Read the report

Read [Discovery Before Collection](training-report.md). The operator identifies
the current user, computer and network configuration, then stages a synthetic
document. No real files are collected and no exfiltration is performed.

Open the [worksheet](hunt-worksheet.md). Predict the process and file events
before looking at the results. Separate the reported behavior from our chosen
command and from the artificial flag instrumentation.

## 4. Understand the four prepared abilities

**Local:** open Caldera's Abilities view and search for `WW-TRAIN-001` and your
run label. **Hosted:** follow the instructor's view. Setup has already built
these objects; you do not need to author flag-bearing commands during the CTF.

| Ability | Behavior | Reference action |
|---|---|---|
| Discover current user | Identify the execution account | `whoami.exe`, wrapped with the discovery marker |
| Discover computer name | Identify the target | `hostname.exe` |
| Discover network configuration | Inspect interfaces and addresses | `ipconfig.exe /all` |
| Stage a synthetic document | Create and copy training text | PowerShell creates a run directory and copies a synthetic file into `staging` |

Each uses the Windows `psh` executor. Inspect the command, prerequisites and
expected output. The staging action refuses to overwrite an existing run
directory. Flags are exercise instrumentation, not real-world detection logic.

Atomic Red Team is also installed. During the instructor's walkthrough you can
inspect a test without executing it on your own Windows lab VM:

```powershell
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1
Invoke-AtomicTest T1059.001 -ShowDetailsBrief
```

Creating your own ability is an optional follow-up; use a separate copy and
keep the prepared CTF profile intact.

## 5. Review the prepared adversary

Open Caldera's Adversaries view and select **`WW-TRAIN-001 <run-label>`**.
The default public profile is **`WW-TRAIN-001 practice-01`**. For the conference,
use the profile name supplied by the instructors.

Verify the selected abilities are ordered as follows:

1. Discover current user.
2. Discover computer name.
3. Discover network configuration.
4. Stage a synthetic document.

An adversary profile groups the actions. An operation records their execution.
Do not select an unrelated built-in Caldera profile. If the workshop profile
is missing, rerun the setup/bootstrap step; do not silently substitute another.

To learn how it was built afterward, create a new uniquely named adversary,
add copies of these four abilities in that order and save it. The
[reference implementation](scenario/README.md) shows the full construction.

## 6. Run one controlled operation

**Hosted:** the instructor performs these steps. Record the profile, target,
operation ID and UTC evidence window they provide.

**Local:**

1. Open **Agents**. Identify the live, trusted Sandcat session on `win11-victim`;
   check its hostname, user and recent check-in.
2. Change that agent's **Group** to **`de&th`**, matching the walkthrough.
   Leave `win-dc` and `win-server` in `red`. Verify that `de&th` contains only
   `win11-victim` before creating the operation. This is a group you assign,
   not one setup creates automatically.
3. Open **Operations → Start New Operation** and use these settings:

| Option | Select | Why |
|---|---|---|
| Operation Name | `De&thCON` | A recognizable name for this run. |
| Adversary | `WW-TRAIN-001 practice-01` | The four prepared workshop actions. Use the instructor's profile if a different run label was supplied. |
| Fact Source | `basic` | Keep the walkthrough's fact source; no custom facts are needed for these four actions. |
| Group | `de&th` | Runs against the Windows 11 target only. Do not select `All groups` or `red` for this exercise. |
| Planner | `atomic` | Runs the abilities in the adversary profile's order. This planner is separate from the Atomic Red Team tool. |
| Obfuscators | `plain-text` | Keeps the commands readable for the hunt. |
| Autonomous | `Run autonomously` | Executes the prepared actions without individual command approvals. |
| Parser | `Use Default Parser` | Keeps the default output parsing. |
| Auto Close | `Keep open forever` | Leaves the operation open while you inspect results and hunt evidence. |
| Run State | `Run immediately` | Begins execution when you click Start. |
| Jitter (sec/sec) | `2` / `8` | Uses a randomized check-in interval of 2–8 seconds during the operation. |

4. Review the selected profile and group, then click **Start** once. Allow for
   agent check-in delays; do not launch duplicate operations.
5. Inspect all four link results. Record the operation ID, indexed hostname and
   UTC start/end times. A successful command does not prove its logs arrived.
6. Keep the operation open and leave cleanup until after the Kibana hunt and
   evidence capture. `Keep open forever` is a UI setting, not an instruction
   to leave the lab running indefinitely.

A run label identifies a staging directory. To run again, preserve the evidence,
then follow the [instructor reset instructions](instructor/README.md#reruns-and-cleanup)
or use a new configuration/run label. Repeating the same label against an existing
directory intentionally fails rather than overwriting evidence.

## 7. Hunt the flags in Kibana

Open **Discover → War Wagon logs** (`logs-*`). Hosted attendees use the data view
assigned by the instructor if it has a different name. Select an absolute time
window around the operation and scope to the actual indexed hostname.

Start with process creation, replacing the example hostname as needed:

```text
host.name : "win11-victim" and event.code : "1" and data_stream.dataset : "windows.sysmon_operational"
```

Inspect `process.name`, `process.command_line`, `user.name`, `@timestamp`,
`process.entity_id` and `process.parent.entity_id`. Find the discovery marker
in a discovery-related command line.

Then investigate file creation:

```text
host.name : "win11-victim" and event.code : "11" and data_stream.dataset : "windows.sysmon_operational"
```

Find the staged filename under `C:\WarWagonTraining\<run-label>\staging\`.
Use `file.path` and `process.entity_id` to connect it to its creating process.
Inspect raw JSON if your displayed fields differ. Nearby timestamps alone do
not prove a parent/child relationship.

Submit both flag strings in `{flag}` format, including the braces (omit the staging filename’s `.txt` extension), exactly and complete the worksheet with event/document
IDs, host, UTC times, command/path and supporting process relationships. Explain
what the evidence proves and what remains uncertain. Both local and hosted
participants find the answers in Kibana; reading a flag from configuration is
not completion.
