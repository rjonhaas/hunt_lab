# Instructor setup and reference solutions

[Participant guide](../participant-guide.md) · [Repository home](../../../README.md)

## Prepare the configuration

The default installation loads `WW-TRAIN-001 practice-01` using the public
practice markers in [practice.json](../scenario/practice.json).

For the conference, prepare the same configuration for local and hosted runs:

1. Copy `practice.json` to `.war-wagon/config.json` in the repo root.
2. Set a fresh `run_label` and the two conference flags. Keep the three keys;
   labels must be lowercase letters/digits/hyphens, and flags must match
   `\{[A-Za-z0-9_-]{1,80}\}` (for example, `{WW_DISCOVERY_2026}`).
   Include the braces in the configuration and CTFd answers. Flags must differ.
3. Supply this configuration privately to local attendees before setup. Place
   the same configuration in the hosted checkout before bootstrap.
4. Run setup. Bootstrap preloads and reads back the four abilities and profile.
   It does not start an operation. Private configuration overrides practice.

`.war-wagon/` is ignored by Git but is shared into the lab VM for bootstrap.
Local operators can inspect the flags. Grade Kibana evidence and explanation,
not secrecy from the owner of a local lab. Neither credentials nor private flag
values belong in commits, screenshots or published evidence packages.

To load a new configuration in an existing running lab:

```text
vagrant ssh docker-host -c 'cd /vagrant/docker && sudo docker compose run --rm bootstrap'
```

Identical objects are verified and reused; interrupted imports can finish on
retry. Conflicting existing objects stop setup without being overwritten.
Changing the run label or flags creates a new profile; select the intended one.

## Before attendees connect

Verify the profile and all four abilities in Caldera, a single live target,
Fleet enrollment and recent Sysmon events. Run the selected operation once and
verify both flags in Kibana using a restricted learner account.

Fresh Windows provisioning installs the narrow Sysmon FileCreate rule for
`C:\WarWagonTraining\`. Existing targets need the
[telemetry preparation script](../scenario/enable-file-telemetry.ps1) before the run.
Use the [evidence verifier](../scenario/README.md#verify-evidence) and review the
learner workflow as well. Service readiness alone does not prove the CTF works.

Hosted attendees receive Kibana access only. Publish the target hostname,
operation ID and absolute UTC evidence window. Keep Caldera execution and resets
with the instructors. Set up CTFd with the same two flags as the configuration.

## Reruns and cleanup

Prefer a new `run_label` for each run, keeping the same flag values for the same
conference challenges. Rebootstrap to load its profile, then select that profile
for the next operation. Old profiles remain; do not confuse their run labels.

After grading/evidence capture, a local operator may remove only their exact
`C:\WarWagonTraining\<run-label>` directory on the selected target and rerun the
same profile. Do not remove the whole training root or delete Elastic evidence.
Hosted cleanup is instructor-controlled.

## Reference solutions and validation

- [Ability/profile generator, preloader and evidence verifier](../scenario/README.md)
- [Hosted rehearsal evidence](../scenario/rehearsal.md) — prior revision, not proof of a fresh focused build

## Remaining release checks

Rehearse a fresh focused local build, both flags with a restricted learner
account, concurrent hosted access, instructor operation timing and scoped
cleanup. Distribute the same conference configuration to local participants
and load its flag values into CTFd. Existing full-lab installations do not prove
the focused build passes these checks.

Reference implementation and rehearsal artifacts can reveal how the challenge
works. Grade the participant's independently collected evidence and explanation.
