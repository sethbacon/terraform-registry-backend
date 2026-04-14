# 5. Fire-and-Forget Webhooks

**Status**: Accepted

## Context

When an SCM provider (GitHub, GitLab, Azure DevOps, Bitbucket) sends a webhook notification for a tag push, the registry must process it to auto-publish a new module version. This involves:

1. Validating the webhook signature (HMAC or provider-specific scheme).
2. Parsing the event payload to extract the tag name.
3. Downloading the module source from the SCM at that tag.
4. Uploading the archive to storage.
5. Creating the module version record in the database.
6. Optionally queuing a security scan.

Steps 3-6 can take several seconds to minutes depending on module size and network conditions. Holding the HTTP response open for this duration risks webhook delivery timeouts (GitHub times out at 10 seconds, GitLab at 30 seconds).

The implementation in `internal/api/webhooks/scm_webhook.go` uses `safego.Go()` to spawn a background goroutine with a 10-minute context timeout for processing. The HTTP handler returns 200 immediately after signature validation. The `scm_webhook_events` table tracks processing state (`processing`, `completed`, `failed`, `skipped`).

## Decision

Process webhook events asynchronously using fire-and-forget goroutines:

- The HTTP handler validates the webhook signature, logs the event to `scm_webhook_events`, and returns HTTP 200 immediately.
- A background goroutine calls `SCMPublisher.ProcessTagPush()` with a 10-minute timeout.
- On success, the event is marked `completed`.
- On failure, the event is marked `failed` with the error message stored.
- No automatic retry is performed (retry was deferred to a future phase; see Phase 2.1 in the roadmap for the webhook retry implementation).

## Consequences

**Easier**:
- Webhook endpoints respond within milliseconds, well within provider timeout limits.
- The implementation is straightforward: no message queue, no retry infrastructure, no dead-letter handling.
- Failed events are visible in the webhook events table for manual investigation.
- Background processing uses the existing `safego.Go()` utility with panic recovery.

**Harder**:
- Failed webhook processing is silently lost unless an operator monitors the `scm_webhook_events` table or logs.
- Transient failures (SCM API rate limits, temporary network issues, storage backend hiccups) result in permanently missed module versions.
- No backpressure mechanism: a burst of webhook events spawns unbounded goroutines.
- Manual remediation requires re-pushing the tag or manually triggering the publish workflow.
- The webhook retry job (Phase 2.1) was added later to address these limitations by polling for failed events and retrying with exponential backoff.
