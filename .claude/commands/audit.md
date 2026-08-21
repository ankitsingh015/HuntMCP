---
description: Run a full HuntMCP engagement (recon -> scan -> chain -> exploit -> report) against an authorized target via the huntbrain orchestrator.
---

Invoke the `huntbrain` agent to run a full authorized security engagement
against: $ARGUMENTS

Before doing anything else, huntbrain must confirm real scope/authorization
details for this target and write `engagement.yaml` (see
`engagement.yaml.example` for the format) if one doesn't already exist for
this engagement — do not proceed to recon without it.
