# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for the Terraform Registry Backend project.

## What is an ADR?

An Architecture Decision Record captures an important architectural decision made along with its context and consequences. We use the [Michael Nygard template](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions) with the following sections:

- **Title** -- A short noun phrase describing the decision
- **Status** -- Accepted, Deprecated, or Superseded
- **Context** -- The forces at play, including technical, political, social, and project constraints
- **Decision** -- The change we are proposing or have agreed to implement
- **Consequences** -- What becomes easier or harder as a result of this decision

## Index

| ADR                                         | Title                             | Status     |
| ------------------------------------------- | --------------------------------- | ---------- |
| [001](001-scope-based-rbac.md)              | Scope-Based RBAC                  | Accepted   |
| [002](002-postgresql-as-primary-store.md)   | PostgreSQL as Primary Store       | Accepted   |
| [003](003-storage-backend-abstraction.md)   | Storage Backend Abstraction       | Accepted   |
| [004](004-jwt-plus-apikey-dual-auth.md)     | JWT + API Key Dual Authentication | Accepted   |
| [005](005-fire-and-forget-webhooks.md)      | Fire-and-Forget Webhooks          | Accepted   |
| [006](006-in-memory-rate-limiting.md)       | In-Memory Rate Limiting           | Superseded |
| [007](007-setup-wizard-one-time-token.md)   | Setup Wizard One-Time Token       | Accepted   |
| [008](008-module-scanning-architecture.md)  | Module Scanning Architecture      | Accepted   |
| [009](009-network-mirror-protocol.md)       | Network Mirror Protocol           | Accepted   |
| [010](010-binary-mirror-custom-protocol.md) | Binary Mirror Custom Protocol     | Accepted   |

## Creating a New ADR

1. Copy the template below into a new file named `NNN-short-title.md`.
2. Fill in all sections.
3. Add an entry to the index table above.

### Template

```markdown
# NNN. Short Title

**Status**: Accepted | Deprecated | Superseded by [NNN](NNN-xxx.md)

## Context

[Describe the forces at play]

## Decision

[Describe what we decided]

## Consequences

[Describe what becomes easier or harder]
```
