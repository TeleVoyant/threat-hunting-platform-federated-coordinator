# Contributing

Thanks for your interest in improving apt-fl-coordinator. This is an open federation
component — contributions from participating organisations and the wider community are
welcome.

## Ground rules

- Be respectful — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- By contributing you agree your work is licensed under [Apache-2.0](LICENSE).
- For anything affecting the **wire protocol** or **security model**, open an issue to
  discuss before sending a large PR.

## Development setup

```bash
python -m venv venv && . venv/bin/activate
pip install -r requirements.lock.txt
PYTHONPATH=. OMP_NUM_THREADS=1 python tests/test_unit.py
PYTHONPATH=. OMP_NUM_THREADS=1 python tests/test_e2e.py
```

## Pull-request checklist

- [ ] `tests/test_unit.py` and `tests/test_e2e.py` pass.
- [ ] New behaviour has a test (security-relevant changes MUST add a regression test —
      e.g. a new rejection path, a new signed message field).
- [ ] No new dependency on any external org platform — the server stays self-contained
      (imports only `flproto`, `coordinator`, and third-party libs in `requirements.txt`).
- [ ] Wire-format changes update [PROTOCOL.md](PROTOCOL.md) **and** bump the message
      `type` version (`*.v1` → `*.v2`) when breaking.
- [ ] Secrets, certs, and validation data are never committed (see `.gitignore`).

## Design invariants (please preserve)

- **Trust boundary:** the coordinator shares no auth/state with any org platform.
- **No raw data:** only model parameters cross the boundary; nothing in the server should
  ever require an org's raw telemetry.
- **Verify-before-trust:** every org→coordinator message is signature + nonce + freshness
  + hash checked; every coordinator→org artifact is signed.
- **Fail safe:** validation/aggregation failures leave the round open and never silently
  accept an unverified contribution.

## Areas that welcome help

- Sparse/large model handling in `flproto/dataset.py`.
- OCSP-based revocation (alternative to the current CRL).
- Alternative aggregation strategies behind a pluggable interface.
- A second-language reference client conforming to PROTOCOL.md.
