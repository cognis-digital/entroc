# entroc

**C (C99)** — Windowed Shannon-entropy scanner — flags packed/encrypted/embedded-key regions.

[![ci](https://github.com/cognis-digital/entroc/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/entroc/actions/workflows/ci.yml)
![lang](https://img.shields.io/badge/lang-C-informational)
![license](https://img.shields.io/badge/license-COCL%201.0-2ea043)

Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** — 370+ single-purpose, self-hostable tools. Like every tool in the suite, `entroc` is single-purpose, emits machine-readable JSON, and exits non-zero when it finds something (CI-friendly).


<!-- cognis:example:start -->
## 🔎 Example output

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
  "id": "1234567890",
  "name": "John Doe",
  "email": "johndoe@example.com",
  "phone": "+1-555-1234"
}
```

<!-- cognis:example:end -->

## Build / run

```bash
gcc -O2 -std=c99 -o entroc entroc.c -lm
./entroc suspicious.bin
```

## Usage

```
entroc <file> [--window N] [--step N] [--threshold F]
  --window      window size in bytes        (default 256)
  --threshold   min entropy in bits to flag  (default 7.0)
```

## Output

A JSON object on stdout. Exit code **2** when findings exist, **0** when clean, **1** on error — so you can gate CI/pipelines on it.

## License

COCL 1.0 — see [LICENSE](LICENSE). Commercial use → licensing@cognis.digital
