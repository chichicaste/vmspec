# External VM test reference

## Anti-Slop CTF 2026: Parallax Cartridge

Upstream: [Abdelkad3r/Anti-SlopCTF-2026](https://github.com/Abdelkad3r/Anti-SlopCTF-2026), challenge [reverse/parallax-cartridge](https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/reverse/parallax-cartridge).

This Reverse challenge contains a custom VM/state-continuation test case. The handout includes a 2 MB stripped Go service executable and a starter QAR cartridge. The cartridge carries VM cells, making it useful as an external analysis target and format/frontend exercise.

Download the two test artifacts with upstream SHA-256 verification:

```console
python tools/fetch_antislop_vm.py
```

Artifacts are stored under `data/external/antislopctf-2026/parallax-cartridge/` and ignored by Git. Expected hashes:

- `parallax-cartridge`: `4cbddae4588ad2673d5475ff7d01cd4d0276b225eeacadc14f1f3b0f49292eef`
- `starter.qar`: `745eaaf2e5ae12ddc4bfd14bd6ad041572a38ff9915d4c178142d288b12222bc`

The upstream writeup describes the QAR layout and its five-cell visible program. Keep the upstream writeup and artifacts as the reference; this repository does not redistribute or modify them.

### VMSpec integration status

This is not a drop-in input for the current Code Virtualizer frontend. It is a Go service with a custom QAR VM rather than the existing raw x86 handler-table blob. Before running it through the full pipeline, add a frontend that identifies/extracts VM dispatch and maps the cartridge cells into an analysis representation. Until then, use it for format analysis and as a candidate for a future frontend/equivalence fixture.

The upstream solve script can contact the original remote service. Do not run it as part of local tests; the local artifacts above are sufficient for static analysis.
