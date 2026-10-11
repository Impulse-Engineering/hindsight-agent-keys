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
