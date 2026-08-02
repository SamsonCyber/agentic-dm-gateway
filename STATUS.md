# Status and reproducibility

| Axis | State |
|------|--------|
| Implemented | Yes. Library + optional Discord adapter. Zero required runtime deps for core. |
| Independently validated | Yes. 12 unit tests in `tests/test_security.py` (allowlist, PIN, kill, rate, injection, redaction). |
| Maintained | Yes. Public under [SamsonCyber/agentic-dm-gateway](https://github.com/SamsonCyber/agentic-dm-gateway). |

## What is validated

- Allowlist / deny
- PIN open and TTL behavior (as coded)
- Kill switch
- Rate limits
- Injection heuristic block list
- Secret redaction and image-beacon strip on output
- Pipeline precheck orchestration

## What is not claimed

- Full LLM-judge injection defense (regex heuristics only; README Limits section).
- Live Discord integration tests (need bot token; not in CI).
- Perfect secret format coverage (best-effort patterns).

## Reproduce

```bash
python scripts/repro.py
```

Success line: `REPRO_OK agentic-dm-gateway unit suite`

CI: `.github/workflows/ci.yml` runs the same command on push/PR.
