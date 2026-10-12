# Coding standards

Reviewers apply these to every PR. Each rule is a judgement call that no linter makes; ruff, shellcheck and actionlint run in CI.

1. **Check the effective configuration.** Anything that validates configuration reads it as upstream will at runtime: the same sources (the process environment and any `.env` upstream loads), the same parsing (for example `value.lower() == "true"` with no strip), and the same defaults. The test cites the upstream code it mirrors.
2. **Bound every write that unauthenticated input can trigger.**
   - Limit it per client (an IPv4 address, or an IPv6 /64) and in total.
   - Record that the limit was reached.
   - Cap the memory that tracks clients. A full table must never reset into "allow all".
3. **Make reserved values unforgeable.** A sentinel stored beside client-supplied values uses a form client input cannot produce.
4. **Keep docs true to the code.** In the same PR, check every README row, code comment and config comment that states behaviour against the code it describes.
5. **Pin what runs.** Base and tool images by digest, actions by commit SHA, Python tools by hash. A new pin carries its version as a trailing comment.
6. **Make fakes honour the contract.** A fake for an external CLI applies the call's output-shaping flags (gh `--jq` through jq) or the test asserts the full argument list, so dropping or changing a flag turns a test red.
7. **Fail closed in every window.** For each step that restarts, redeploys or reconfigures the app (in code, scripts or runbooks), name the auth state during and after it. Anything that reopens access waits on a verified result (a completed deploy with the expected digest, a keyless 401), never on a queued action. A check that guards a destructive step reports failure when any part of it fails.
