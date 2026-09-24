# Contributing

Bug reports and pull requests are welcome.

## Before opening a pull request

- Keep changes focused and use Conventional Commit messages (for example,
  `fix: handle encoded probe paths`).
- Add or update tests for behavior changes. Fuzz tests should be deterministic
  for their seed corpus and must not depend on network access.
- Run `make check` and include relevant results in the pull request.
- Keep the decoy archive harmless and within its documented uncompressed-size
  limit.

## Pull requests

Describe the problem, the change, and any compatibility impact. Do not include
real credentials, scanner payloads that cause resource exhaustion, or private
request data in issue reports.
