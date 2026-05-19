# Contributing to agent-phone (Python)

Thanks for your interest. This port exists to track the [TypeScript reference](https://github.com/p-vbordei/agent-phone). The most useful contributions are bug fixes, conformance tightening, and documentation improvements that keep the port in lockstep with the spec.

## Getting set up

```bash
git clone https://github.com/p-vbordei/agent-phone-py
cd agent-phone-py
uv sync --extra dev
uv run pytest -v
uv run ruff check .
```

The full test suite (31 tests) runs in under a second.

## Wire-format contract — read this first

Any change to `src/agent_phone/noise.py`, `src/agent_phone/frame.py`, or `src/agent_phone/envelope.py` **must** keep `test_c4_frame_determinism` passing. That test reads `vectors/c4.json`, which is the shared hex vector pinned by the [TS conformance suite](https://github.com/p-vbordei/agent-phone/tree/main/conformance). If you change byte-level behaviour, you've broken interop with every other port — open an issue first so the spec can move with you.

Same goes for the Ed25519→X25519 derivation in `src/agent_phone/_ed_to_x.py`. The construction is `SHA-512(seed)[0..32]` + RFC 7748 clamp; this is *not* HKDF, *not* BIP-32. See [docs/architecture.md](docs/architecture.md) for why.

## Filing issues

Useful issue reports include:
- A failing `pytest` invocation, ideally one that fits in a single test function.
- The TS reference's behaviour on the same input (link to a TS test or `bun examples/demo.ts` output).
- Python version and OS.

## Pull requests

- Run `uv run ruff check .` and `uv run pytest -v` locally before opening.
- Keep diffs focused. Cross-cutting refactors are easier to review (and easier to mirror to the Rust port) as separate PRs.
- New features need a test. Behavioural changes need both a test and a `CHANGELOG.md` entry.
- Be ready to mirror anything substantive to [`agent-phone-rs`](https://github.com/p-vbordei/agent-phone-rs).

## License

By contributing you agree your contributions are licensed under Apache-2.0, matching the rest of the project.
