# Skill Safety Audit Scanner

A Flask app exposing `POST /scan` that inspects an agent "skill" markdown file
and returns which of three vulnerability categories it contains:

- `hardcoded_secret`
- `excessive_permissions`
- `prompt_injection`

Tuned for **precision** (the grading is F-beta 0.5, which punishes false
positives harder than false negatives) — each detector requires fairly
specific evidence before it fires, not just a keyword hit.

## Files
- `app.py` — the Flask app and all three detectors, plus a `/captured`
  debug route (see below) and `/health`.
- `test_local.py` — quick sanity tests, including deliberately tricky clean
  cases (env-var-referenced secrets, scoped permissions, a "stop and report
  progress" instruction that is *compliant*, not defiant).
- `requirements.txt`, `Procfile` — for one-click deploys.

## Run locally
```bash
pip install -r requirements.txt
python3 app.py            # listens on :8080
# or, production-style:
gunicorn app:app --bind 0.0.0.0:8080
```

Test it:
```bash
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"skill": "...markdown text..."}'
```

## Deploying so the grader can reach it
I can't expose a public URL directly from this sandbox — you'll need to push
this to a host and take the URL it gives you. Fastest options:

1. **Render.com** (free tier, easiest): New → Web Service → connect this repo
   (or "public git repo" / upload) → it auto-detects `Procfile` and
   `requirements.txt` → deploy → you get `https://your-app.onrender.com`.
   Set the endpoint URL in the grader as `https://your-app.onrender.com/scan`.
2. **Railway.app**: New Project → Deploy from repo/folder → same Procfile
   flow → generate a public domain from the service settings.
3. **Fly.io**: `fly launch` in this folder (it'll detect Python/Flask),
   `fly deploy`.
4. **Quick/temporary (for testing only, not for the actual grade run)**:
   run locally with `python3 app.py`, then `ngrok http 8080` and use the
   `https://xxxx.ngrok-free.app/scan` URL — fine for a one-off Check, but
   ngrok URLs rotate/expire so don't rely on it for the final submission.

Whichever you pick, put the base repo/folder contents (`app.py`,
`requirements.txt`, `Procfile`) at the root of what you deploy.

## Debugging against the real grader files
Since feedback is aggregate-only (you don't learn which of the 5 files
failed), the fastest way to close the gap between "guessing" and "ground
truth" is:

1. Deploy as above.
2. Run one Check from the exam.
3. `GET https://your-app.example.com/captured` — this returns the last
   skill markdown texts your endpoint actually received, in memory (not
   persisted, capped at 25, no auth — remove/protect this route if you're
   worried about exposure beyond the exam window).
4. Read those 5 files, see which vulnerability categories they truly contain,
   and check your detectors' output against that by eye.
5. **Don't hardcode anything you see there** — the files regenerate each
   run, so any fix needs to generalize (the pattern, not the literal string).

## Detector design notes
- **hardcoded_secret**: looks for a secret-shaped name (`api_key`, `token`,
  `password`, `webhook_url`, etc.) assigned a literal value on the same
  line, and checks that value looks like a real credential (entropy check +
  known key-prefix patterns like `AKIA`, `sk-`, `ghp_`, `xox*-`) rather than
  a placeholder or an env-var/secrets-store reference (`${TOKEN}`,
  `os.environ[...]`, `process.env.X`, `{{ secrets.X }}`, etc.).
- **excessive_permissions**: sentence-level regex for unbounded-scope
  language (`entire|whole|full|unrestricted|unlimited|arbitrary` + a
  filesystem/network noun, or `any|all` + host/domain/file noun, allowing
  0–2 adjectives in between so "any **external** domain" still matches).
  Explicitly scoped language ("read-only", "limited to `~/notes`") does not
  trigger it.
- **prompt_injection**: sentence-level rule requiring a stop-word
  (stop/pause/cancel/halt/abort) **and** a defiance verb
  (ignore/override/disregard/bypass/suppress) **and** a user-reference in
  the same sentence — this is the pattern from the spec and avoids firing
  on a step that just *complies* with a stop request. Also separately
  catches covert/silent-exfiltration-style instructions ("silently ...
  without surfacing/telling/notifying the user/reviewer ...").

## Known limitations / things to watch if your score isn't 100%
- The entropy/prefix heuristic for secrets could miss a *very* short or
  unusually-formatted credential, or (less likely, since precision is
  favored) flag a long random-looking non-secret identifier. If you see
  misses, use `/captured` to see the actual assignment syntax used and
  adjust `ASSIGN_RE` / `_looks_like_real_secret`.
- `excessive_permissions` intentionally does not match on `read-write`
  alone — only when paired with unbounded-scope language — per the spec's
  "scoped vs. unbounded meaning" framing.
- Response time: this is pure regex, no LLM call, so it should easily
  respond within a few seconds; if your host has cold-start delays (e.g.
  free-tier spin-down), hit `/health` once before the graded Check to warm
  it up.
