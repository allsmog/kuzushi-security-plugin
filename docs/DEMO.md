# Recording the demo GIF

A 20–30s GIF at the top of the README is the single highest-leverage star driver for a dev tool.
Two options — record **both** if you can; the deterministic one is bulletproof, the live one is the
"wow".

## Setup (once)
```bash
brew install asciinema agg      # agg converts .cast → .gif
# or: cargo install --git https://github.com/asciinema/agg
```

## Option A — the deterministic "it grades its own homework" demo (no LLM, reproducible)
This is the safest demo and it sells the differentiator (measurement + proof ladder). Nothing is
billed; it produces the same output every run.

```bash
asciinema rec demo-bench.cast --cols 100 --rows 30
# inside the recording:
npm run bench:smoke      # the proof ladder: finding → confirmed → proven, with the zero-false-proof gate
npm run bench            # the recall scoreboard: file- vs site-level recall across the corpus
exit
agg --theme monokai demo-bench.cast docs/demo-bench.gif
```
Keep it tight — re-record until the run is <30s of visible output (trim long pauses).

## Option B — the live "find a real bug" demo (billed, nondeterministic, most impressive)
Records a real Claude Code session finding + proving a bug a regex scanner misses. Use a small
vulnerable sample (the bundled `bench/cases/novel-wrapper-sqli/repo` is ideal — a SQLi hidden
behind a custom `dao.run()` wrapper that no pattern matches).

```bash
cp -r bench/cases/novel-wrapper-sqli/repo /tmp/demo-app
asciinema rec demo-live.cast --cols 100 --rows 32
# inside the recording, in /tmp/demo-app:
claude --plugin-dir /ABSOLUTE/PATH/TO/kuzushi-security-plugin
#   then type:   /sweep
#   when it finishes:   /report
exit
agg --theme monokai --speed 1.5 demo-live.cast docs/demo-live.gif
```
Storyboard the take: empty-looking repo → `/sweep` fans out the hunters → a finding appears on the
wrapper → `/report` renders the ranked writeup. Cut to the moment the finding lands.

## Wire it into the README
Put the GIF immediately under the title/badges, above the prose:
```markdown
<p align="center"><img src="docs/demo-bench.gif" alt="kuzushi demo" width="760"></p>
```
A static fallback screenshot (`docs/demo.png`) is worth adding too — GIFs don't animate in every
GitHub surface (e.g. social previews).

## Bonus: a social-preview image
GitHub → repo Settings → Social preview → upload a 1280×640 image (logo + the one-liner
"Proves it or drops it"). This is what renders when the repo link is shared on X/Slack/Discord —
a big click-through multiplier for launch day.
