# gosec baseline exceptions log

`gosec-baseline.json` is the accepted-risk register for this backend: any finding it
contains is silently suppressed by CI's `gosec-compare.py` (only genuinely *new*
findings fail the build). This file is the audit trail — every time
`scripts/update-gosec-baseline.sh` adds a new unsuppressed (`nosec:false`) finding to
the baseline, it must be run with `--reason "..."`, which appends an entry here.
Changes to this file (and to `gosec-baseline.json`) require `@security-team` review
per `.github/CODEOWNERS`.

Prior to the introduction of this control (2026-07-10, issue #563 finding [22]),
baseline regenerations were reviewed and merged via ordinary PR review without a
dedicated per-finding justification field recorded here — see the PR descriptions for
`gosec-baseline.json` changes in this repo's history (e.g. #569, #573, #574, #576,
#577) for the context recorded at the time. This log only covers acceptances made
from 2026-07-10 onward.
