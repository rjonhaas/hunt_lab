# Discovery Before Collection

**War Wagon training intelligence report · WW-TRAIN-001 · Draft 1**

This is a synthetic training narrative, not reporting about a real intrusion or
attribution to an actual actor. The accompanying exercise is pending rehearsal.

## Intelligence summary

An operator with access to a Windows workstation identifies the current user,
computer name, and network configuration. Shortly afterward, the operator
creates a local staging directory and copies a document into it. The sequence
suggests preparation for collection, but legitimate administration can produce
similar behavior. Context and process relationships matter.

The exercise begins with an existing lab agent. It does not simulate initial
access, credential theft, privilege escalation, persistence, or exfiltration.
The staged document contains synthetic training text only. No domain is required.

## Reported sequence

1. **User discovery:** Determine the identity under which commands execute.
2. **System discovery:** Determine the computer name.
3. **Network discovery:** Examine local interface and address configuration.
4. **Local staging:** Create a working directory and copy a document into it.

These are behavioral requirements, not a prescribed script. Choose commands
that reproduce each behavior, explain your choices, and distinguish the
underlying behavior from a particular tool name.

## Investigation questions

- What process and user context would each action leave behind?
- Which evidence could show that staging actually occurred?
- Can you connect the file event to its creating process?
- Which relationships are proven, and which are inferred from timing?
- What legitimate activity could resemble this sequence?

## Lab adaptation

Reproduce only these four behaviors on your assigned Windows lab target. Use a
synthetic source document and a dedicated exercise directory; do not collect
existing user files. The instructor supplies the exercise run label, target,
flag configuration, and safe file locations separately.

Two artificial markers support workshop grading. One appears in a discovery
process command line; the other appears in the staged filename. These markers
are exercise instrumentation, not real-world indicators or detection logic.

## Deliverable

Translate this report into reviewed Caldera abilities and an ordered adversary
profile. Predict the evidence before execution, then investigate the operation
in Kibana and document the evidence for both flags.

Hosted students contribute to Joe's walkthrough; Joe alone executes against the
shared lab. Local students build and execute their own operation. Both groups
use this report and the same challenge definitions.

Read [the participant guide](participant-guide.md), then complete
[the worksheet](hunt-worksheet.md). A completed scenario is a fallback or
post-workshop reference, not the starting exercise.
