# Kuzushi Bench Fixtures

This directory is reserved for deterministic local benchmark fixtures. The
current executable fixture is the temp-repo smoke benchmark:

```bash
npm run bench:smoke
```

Future fixtures should be self-contained, network-free, and assert the proof
ladder rather than only scanner output.
