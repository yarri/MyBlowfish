# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

MyBlowfish is a single-class PHP library for password hashing and verification using the Blowfish (bcrypt) algorithm. It originated from the ATK14 Framework but has no hard dependency on it. The entire implementation lives in one file: `src/my_blowfish.php` (class `MyBlowfish`).

## Commands

Install dev dependencies (required before running tests):
```bash
composer update --dev
```

Run the full test suite:
```bash
cd test && ../vendor/bin/run_unit_tests
```

Tests use the `atk14/tester` wrapper around PHPUnit. There is no separate lint/static-analysis command configured in this repo (Codacy runs externally on push; `.codacy.yml` only excludes `test/**` from analysis).

CI (`.github/workflows/tests.yml`) runs this same test command across PHP 5.6 through 8.5. Keep changes compatible with that whole range — do not use syntax or functions newer than PHP 5.3 without a feature check, matching the `"php": ">=5.3.0"` constraint in `composer.json`.

## Architecture

Everything of substance is in `src/my_blowfish.php`:

- **Configuration via constants, defined once, overridable by the host app before this file loads**: `MY_BLOWFISH_ROUNDS` (default 12, valid range 4–31), `MY_BLOWFISH_PREFIX` (default `$2y$`), `MY_BLOWFISH_ESCAPE_NON_ASCII_CHARS` (default true). The pattern is `if(!defined(...)) define(...)`, so a consumer app sets these constants beforehand to override.
- **Public API surface**: `Filter()` (hash only if not already a hash — idempotent, safe to call on a value that might already be hashed), `Hash()` (alias of `Filter()` kept for backwards compatibility), `GetHash()` (always hashes, even a hash-looking input), `CheckPassword()`, `IsHash()`, `RandomString()`, `EscapeNonAsciiChars()`.
- **Salt handling in `GetHash()`**: the `$salt` parameter can be a full existing hash/salt (`$2a$12$...`), a partial salt, or empty. It's parsed with a regex into prefix + random portion; the random portion is padded/repeated to exactly 22 chars. The final salt must be exactly 29 chars and match `/^\$2[aby]\$[0-9]{2}\$/`, otherwise an exception is thrown. This is how `Filter()`/`CheckPassword()` recompute a hash using the same salt as an existing one to compare.
- **Non-ASCII password handling**: PHP's blowfish crypt has known issues with non-ASCII input (see comment linking php.net/security/crypt_blowfish.php). `EscapeNonAsciiChars()` works byte-by-byte (not char-by-char) so each byte of a multi-byte UTF-8 sequence is escaped independently into a deterministic `\xHH` form. `CheckPassword()` tries verification with escaping both on and off (toggling the option and re-hashing) to stay compatible with hashes created under either historical behavior.
- **`RandomString()`** sources entropy from `random_bytes()` (PHP 7+) → `openssl_random_pseudo_bytes()` → `mcrypt_create_iv()` (PHP 5.x, pre-7.2) → `rand()` as a last-resort fallback (triggers an `E_USER_WARNING` since it's not cryptographically secure). `_EncodeBytes()` is the PHP Password Hashing Framework's base64-like alphabet encoder, reused verbatim.
- **`_CompareHashes()`** uses `hash_equals()` for timing-safe comparison, falling back to `strcmp()` only if `hash_equals()` doesn't exist (pre-PHP 5.6).
- **Error behavior**: `GetHash()` throws plain `Exception` on invalid rounds/prefix/salt. `CheckPassword()` deliberately does *not* throw when given a non-hash second argument — it just returns `false` (this was an intentional change, see CHANGELOG [1.3] — throwing there was considered an antipattern).

## Testing notes

- `test/initialize.php` sets `MY_BLOWFISH_ROUNDS` to 6 (low, for fast tests) before requiring the source file — this is the test bootstrap, loaded automatically by the `atk14/tester` runner.
- `test/tc_my_blowfish.php` contains all test cases in one `TcMyBlowfish extends TcBase` class. Expected hash values in tests (e.g. `test_salting`, `_test_prefix`) are literal pre-computed bcrypt outputs for fixed password+salt pairs — if you change hashing logic, these fixtures need to be recomputed, not just rewritten to pass.
- `$2b$` prefix tests are skipped on PHP 5.3 (no support for that prefix in that version).

## Releases

Version bumps and changes are tracked in `CHANGELOG.md` using Keep a Changelog style with an `[Unreleased]` section at the top. `README.md` documents the public API with runnable examples — keep it in sync with behavior changes to `src/my_blowfish.php`.
