# Security methodology

This document describes how Candor's security and privacy claims are
checked, not just made. It exists because this project found — more than
once — that a comment or a README sentence can describe something that was
true when it was written and silently stop being true as the code changed
around it. See [README.md](README.md)'s Security section for what Candor
actually promises; this document is about how those promises get verified,
and kept verified, over time.

## The core rule: check the code, not the comment

A doc comment, a README sentence, or this very document can all be wrong —
not from carelessness, but because code changes and prose doesn't always
change with it. Concretely, this project has already found real bugs that
looked exactly like this: a comment stating "we trust the topmost header"
next to code that, verified empirically against the actual parsing
library, did the opposite. Before relying on a claim about what the code
does — your own claim, a past claim, or a claim in a comment you're
reading for the first time — check it against the current source. If
there's any way to check it empirically (write a throwaway test, run it
against the real dependency, read the actual library source instead of
trusting its documentation when the two might disagree) rather than reason
about it abstractly, do that instead.

## Zero-trust toward email content

Every field of an incoming email is attacker-controlled by default,
regardless of whether it follows a standard format. "It's a valid
RFC 5322/MIME field" is not evidence of safety — it describes the format,
and the format is exactly what a crafted attack rides inside. This applies
to anything derived from a message that gets used for more than inert
display text: file paths, trust/verification decisions, input to any other
system. Treat it as hostile input first, and prove otherwise. This isn't
hypothetical — the attachment-filename path-traversal bug (below) was
exactly this: a sender-controlled field, trusted because its *shape*
looked like an ordinary filename.

## The regression suite

Every fix for a real security or validation bug gets a permanent test, not
just a fix. These live alongside the code they guard, in modules named
`security_regression_tests` or `architecture_regression_tests` (confirms a
specific fix produces the *correct* result) and `adversarial_input_tests`
(confirms the system *fails safely* against hostile or malformed input —
see below):

- `candor-core/src/inspect.rs`:
  - `mod tests` — the `Authentication-Results` header-selection bug
    (trusts the first/topmost header, not the last) and the
    clause-parsing hardening for SPF/DMARC result extraction.
  - `mod adversarial_input_tests` — garbage/truncated/invalid-UTF-8 raw
    messages, pathologically deep MIME nesting, and hostile
    `Authentication-Results` header text, all asserted to never panic.
- `candor-core/src/body.rs`:
  - `mod security_regression_tests` — the attachment-filename
    path-traversal fix (including the Windows-separator edge case found
    by the test itself, not anticipated in advance) and the folder-name
    cache-path traversal fix.
  - `mod adversarial_input_tests` — null bytes, bidi-override
    characters, multi-kilobyte names, and other malformed filenames/
    folder names fed to both sanitizers, asserted to never panic and
    never produce a result capable of escaping the directory it's
    joined into (checked by actually joining and comparing
    `.parent()`, not by a textual heuristic — see "Test validation"
    below for why that distinction mattered in practice).
- `candor-core/src/config.rs` — `mod security_regression_tests` — local
  file/directory permissions, checked against the actual on-disk mode
  bits, not just that the code runs without error.
- `candor-gui/src/account_tab.rs` — `mod security_badge_tests` — the
  `dkim_aligned`-computed-but-never-read bug (a cryptographically valid
  DKIM signature from an unrelated domain used to show as "all clear").
- `candor-gui/src/main.rs` — `mod architecture_regression_tests` — an
  allowlist-based scan of the GUI crate's own source, enforcing "the GUI
  never writes to the local database directly" as a checked invariant
  instead of a claim nobody re-verifies.

Run the whole suite with `cargo test --workspace` before any push or
release. A failure here means a security or architecture promise this
project has made is no longer true — treat it accordingly, not as routine
test noise to silence.

## Test validation: a passing test has to prove it can fail

A test that would still pass with its fix reverted isn't testing anything
— it's decoration. Before trusting a new regression test (your own or one
you're reviewing), confirm it actually catches the failure it claims to
guard:

- Best: temporarily revert the fix and confirm the test fails, then
  restore the fix. This project's `architecture_regression_tests` suite
  was validated exactly this way — a fake write-function reference was
  injected to confirm the scan actually flags it, then removed.
- Also valuable, and how most of this suite's tests were actually
  *discovered* rather than just confirmed: write the test against the
  suspected-broken behavior *first*. If it fails against the real,
  current code, you've found a live bug, not just written a test for an
  already-fixed one.
- Watch for a test that's quietly stopped exercising what it claims to.
  Code changes around a test more often than the test itself does; a
  passing test suite doesn't mean "nothing changed," only "nothing this
  specific set of assertions happens to catch."
- The flip side of the same discipline: a test's *assertion* can itself
  be wrong, not just the code it's checking. This project's
  `attachment_filename_never_panics_or_escapes_regardless_of_input` test
  originally asserted the sanitized filename must never contain the
  substring `".."` — and failed against the payload `"...."` (four
  literal dots), which contains that substring without being a
  traversal at all. Confirmed empirically (joined the path and checked
  its parent directory matched) that the *production code* was already
  correct; the test was checking a textual property that doesn't
  actually correspond to the real security guarantee. Fixed the
  assertion, not the code. A failing test is exactly as likely to be
  revealing a bad assertion as a bad implementation — check which one
  before "fixing" either.

## Tests are supposed to find failures, not just confirm successes

A suite that only tests inputs expected to succeed is checking half the
story, and the less important half for anything that parses untrusted
input. Per the zero-trust-toward-email-content policy above, real email
*will* eventually be malformed, truncated, oversized, or deliberately
adversarial — the question worth testing isn't just "does this produce
the right answer for well-formed input," it's "does this fail safely
(return an error, return `None`, skip gracefully) instead of panicking,
hanging, or doing something undefined" for input that's actively hostile.
`adversarial_input_tests` modules (`inspect.rs`, `body.rs`) exist
specifically for this and are deliberately organized separately from the
`security_regression_tests`/`mod tests` modules that confirm a specific
fix produces a *correct* result — these confirm the system *fails safely*
against input nothing legitimate would ever produce: empty/truncated raw
messages, invalid UTF-8, thousands of levels of MIME nesting, null bytes
and bidi-override characters in filenames, multi-kilobyte header values.
None of these tests assert a specific expected output; they assert the
code returns or errors instead of panicking, and (for the path-handling
functions) that the result can never actually escape the directory it's
being joined into.

## Never weaken security for testability

If making something easier to test would mean loosening an actual
protection — a bypass flag, a "test mode" that skips real verification, a
mock that diverges from what production actually does — that trade is
backwards, full stop. The fix for hard-to-test security-critical code is
almost always to extract the *pure, deterministic logic* into its own
function and test that in isolation (exactly what happened with
`sanitize_attachment_filename` and `sanitize_folder`, both originally
inline and untestable on their own), not to add a lever that weakens the
real path.

**A known, real tension, flagged rather than worked around**: DKIM
verification (`inspect_dkim`) does genuine cryptographic verification
against a live DNS lookup for the signer's public key — by design, since
that's what makes it independent verification rather than a header
reading. That also makes it slow and network-dependent to exercise in a
fast unit-test loop, the exact kind of pressure that tempts a "just add a
flag to skip the real DNS lookup in tests" shortcut. That has not been
done, and should not be: a flag capable of disabling real DKIM
verification is also capable of being accidentally reachable outside
tests. The actual coverage this project has instead: the pure logic
around DKIM — `domain_aligns`'s alignment check, `extract_auth_result`'s
header parsing, and `security_is_ok`/`summarize_verdict`'s combination of
`dkim_verified`/`dkim_aligned` into what the user actually sees — is all
unit-tested directly, with the real cryptographic verification itself
left to integration-level testing against a real account rather than
mocked. If broader automated DKIM coverage is ever wanted, the right tool
is a local test IMAP/DNS fixture the verification code talks to for
real, not a bypass inside the verification code itself.

## Per-major-release audit

Beyond the regression suite (which only re-checks what's already been
found), do a full top-down pass before each major release: go through
every security and validation claim this project makes — starting with
the README's Security section — and verify each one directly against the
current code, the same way this file's methodology describes. Not just
the pieces that changed since the last release; the whole surface, since
a claim that was true at the last audit can stop being true from a change
made somewhere else entirely (the `dkim_aligned` bug was not introduced by
a change to the DKIM code itself).

## Audit log

Dated entries for each full top-down pass, newest first. Each entry is a
summary; see project memory / commit history for full detail on specific
fixes.

- **2026-10-31** — First full pass. Covered: credential storage and
  zeroization lifecycle, TLS enforcement across every network path, the
  OAuth2 flow (PKCE, CSRF, redirect handling, SSRF hardening, refresh
  concurrency), SQL injection surface, path traversal (attachment
  filenames and cache folder names), local file permissions, D-Bus
  exposure, and the DKIM/SPF/DMARC verification pipeline specifically.
  Found and fixed: OAuth2 SSRF gap (undisabled HTTP redirects), an
  unbounded hang on an abandoned sign-in, three places that silently
  recreated plaintext credential copies the earlier zeroize work had
  closed elsewhere, a refresh-token race between two independent
  background loops, an `Authentication-Results` header-selection bug
  (trusted the last occurrence of a repeated header instead of the
  first), a `dkim_aligned` field that was computed but never actually
  read anywhere, substring-confusable SPF/DMARC parsing, path traversal
  via attachment filenames, world-readable local data files, and one
  README overstatement (crash-dump protection that zeroizing doesn't
  actually provide). This methodology document and the regression suite
  it describes were both written as a direct result of this pass.
  Same-day follow-up: added `adversarial_input_tests` coverage (garbage/
  malformed/pathological input fed directly at the parsing and
  sanitization code, asserting safe failure rather than a specific
  output) and, in the process, found and fixed an incorrect assertion in
  one of the path-traversal tests itself — a case of the test being
  wrong, not the code (see "Test validation" above).
