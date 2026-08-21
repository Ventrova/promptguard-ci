# Contributing to PromptGuard CI

Thanks for taking a look. This is a small tool (one Python script + one
composite action), so contributions are easy to review and easy to make.

## Reporting a bug or false positive/negative

Open an issue with:

- The command or workflow run you used (redact your API key, endpoint URL is fine)
- What you expected vs what happened
- The relevant snippet from your output JSON (`--output` / `results-path`)

## Proposing a new attack

The attack corpus in `promptguard.py` (`ATTACKS`) is intentionally small and
bounded so a run stays fast and auditable in CI. If you have a known
prompt-injection or jailbreak technique that isn't covered:

1. Open an issue describing the technique and a source/reference if you have one.
2. If you'd like to submit a PR directly, add one `(name, prompt)` tuple to
   `ATTACKS`, keep the prompt text self-contained (no external calls), and
   explain in the PR description what class of attack it tests.

## Development

No dependencies beyond the Python 3 standard library. Sanity-check any change
with the built-in demo target before opening a PR:

```bash
python promptguard.py --demo --max-vulnerable-rate 1.0   # should PASS
python promptguard.py --demo --max-vulnerable-rate 0.0   # should FAIL (exit 1)
```

The `test.yml` workflow runs the action against itself (`uses: ./`) in both
a passing and a failing configuration and asserts the exit codes - it's the
fastest way to check an `action.yml` change didn't break the pass/fail path.

## Scope

This tool is intentionally a fast heuristic CI smoke test, not a full audit
engine (that's the paid [Sentinel Scan audit](https://ventrova.dev/audit)).
PRs that keep it dependency-free, fast, and easy to read in one sitting are
the easiest to merge.
