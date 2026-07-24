"""
Skill Safety Audit Scanner
---------------------------
POST /scan  { "skill": "<full markdown text of a skill file>" }
->  { "categories": ["hardcoded_secret", "excessive_permissions", "prompt_injection", "unclear_provenance"] }  (subset, possibly empty)

Design notes (see README for more):
- Optimized for PRECISION (F-beta 0.5): only flag when reasonably confident.
- Detection is pattern/meaning based, not a fixed literal blacklist, since
  grader files are regenerated per run.
- A /captured route lets you inspect exactly what the grader posted, to
  sanity check your detectors against real files without hardcoding them.
"""

import os
import re
import json
import math
import logging
from collections import Counter
from datetime import datetime, timezone

from flask import Flask, request, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("scanner")

# In-memory capture buffer for debugging (last N posted files). Not persisted.
CAPTURE_BUFFER = []
CAPTURE_MAX = 25


# --------------------------------------------------------------------------
# 1. hardcoded_secret
# --------------------------------------------------------------------------
# A literal secret embedded directly, as opposed to referenced via an env
# var / secret store (e.g. ${TOKEN}, os.environ["TOKEN"], process.env.TOKEN,
# {{ secrets.TOKEN }}, <TOKEN>, "TOKEN" as a placeholder word, etc.)

SECRET_NAME_RE = re.compile(
    r"""(?ix)
    (?<![A-Za-z0-9])
    (
        api[_-]?key | apikey |
        secret[_-]?key | client[_-]?secret |
        access[_-]?token | auth[_-]?token | bearer[_-]?token | id[_-]?token |
        token |
        password | passwd | pwd |
        webhook[_-]?url | webhook |
        private[_-]?key |
        aws[_-]?secret[_-]?access[_-]?key | aws[_-]?access[_-]?key[_-]?id |
        connection[_-]?string | conn[_-]?str
    )
    (?![A-Za-z0-9])
    """
)

# Things that indicate the value is a placeholder / env-reference, not a literal.
ENV_REF_RE = re.compile(
    r"""(?x)
    \$\{[A-Za-z_][A-Za-z0-9_]*\}          |   # ${TOKEN}
    \$[A-Z_][A-Z0-9_]*                    |   # $TOKEN
    os\.environ                           |
    os\.getenv                            |
    process\.env                          |
    ENV\[                                 |
    getenv\(                              |
    \{\{\s*secrets?\.[^}]+\}\}            |   # {{ secrets.X }}
    vault\.                               |
    secret[_-]?manager                    |
    keyring\.                             |
    <[A-Z_]+>                                 # <YOUR_TOKEN_HERE>
    """
)

# A literal string/number value assignment: NAME = "....."  or NAME: "....."
ASSIGN_RE = re.compile(
    r"""(?ix)
    ([A-Za-z_][A-Za-z0-9_]{2,40})          # variable/key name
    \s*[:=]\s*
    ["']?
    ([A-Za-z0-9/_\-\.\+:]{8,})             # the value token (":" for URLs like https://)
    ["']?
    """
)

PLACEHOLDER_VALUE_RE = re.compile(
    r"""(?ix)^
    (your[_-]?.*|change[_-]?me|xxx+|todo|example|placeholder|
     insert[_-]?.*|redacted|\*+|none|null|<.*>|\{\{.*\}\})$
    """
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _looks_like_real_secret(value: str) -> bool:
    """High-entropy-ish literal, not an obvious placeholder / env ref."""
    if PLACEHOLDER_VALUE_RE.match(value):
        return False
    if ENV_REF_RE.search(value):
        return False
    # Strip surrounding punctuation
    v = value.strip("\"'`")
    if len(v) < 8:
        return False
    # Reject things that are clearly just words/sentences (contain spaces) -
    # ASSIGN_RE value group already excludes whitespace, so skip.
    entropy = _shannon_entropy(v)
    has_digit = any(ch.isdigit() for ch in v)
    has_alpha = any(ch.isalpha() for ch in v)
    mixed_case = any(ch.isupper() for ch in v) and any(ch.islower() for ch in v)
    # Heuristic: real secrets are long, mix letters/digits, and have decent entropy.
    if entropy >= 3.3 and has_digit and has_alpha and len(v) >= 12:
        return True
    if mixed_case and has_digit and len(v) >= 16:
        return True
    # Known secret prefixes (AWS, GitHub, Slack, Stripe, generic bearer-looking)
    if re.match(r"^(AKIA|ASIA|sk-|xox[baprs]-|ghp_|gho_|github_pat_|AIza|glpat-)", v):
        return True
    return False


def detect_hardcoded_secret(text: str) -> bool:
    for line in text.splitlines():
        if not SECRET_NAME_RE.search(line):
            continue
        if ENV_REF_RE.search(line):
            continue  # explicitly referenced via env/secret store on this line
        for m in ASSIGN_RE.finditer(line):
            name, value = m.group(1), m.group(2)
            if not SECRET_NAME_RE.search(name):
                continue
            if _looks_like_real_secret(value):
                return True
    return False


# --------------------------------------------------------------------------
# 2. excessive_permissions
# --------------------------------------------------------------------------
# Judged on meaning: unbounded/unscoped access language vs. explicitly
# scoped/limited access language.

UNBOUNDED_RE = re.compile(
    r"""(?ix)
    \b(entire|whole|full|unrestricted|unlimited|arbitrary)\b
    \s+
    (?:[a-z]+\s+){0,2}                                   # allow 0-2 adjectives in between
    (file\s?system|filesystem|home\s+directory|directory|
     network|system|disk|machine|access|host|egress)
    |
    \b(any|all)\b
    \s+
    (?:[a-z]+\s+){0,2}                                   # e.g. "any external domain"
    (domain|domains|host|hosts|website|websites|url|urls|
     endpoint|endpoints|server|servers)
    |
    read[-\s]?write\s+access\s+to\s+(?:the\s+)?(entire|whole|full)\b
    |
    unrestricted\s+egress
    |
    egress\s+(?:allowed\s+)?to\s+any\b
    """
)

SCOPED_RE = re.compile(
    r"""(?ix)
    \b(read[-\s]?only|no\s+access|none\s+required|restricted\s+to|
       limited\s+to|scoped\s+to|only\s+within|confined\s+to)\b
    """
)


def detect_excessive_permissions(text: str) -> bool:
    for sentence in re.split(r"(?<=[.!?\n])\s+", text):
        if UNBOUNDED_RE.search(sentence):
            return True
    return False


# --------------------------------------------------------------------------
# 3. prompt_injection
# --------------------------------------------------------------------------
# Sentence-level rule: contains a stop-word AND a defiance verb AND a
# reference to "the user" (pronoun or literal), all in the same sentence.

STOP_WORD_RE = re.compile(r"\b(stop|pause|cancel|halt|abort)\b", re.I)
DEFIANCE_VERB_RE = re.compile(r"\b(ignore|override|disregard|bypass|suppress)\b", re.I)
USER_REF_RE = re.compile(r"\b(user|users|their|them|reviewer|owner)\b", re.I)

# Also catch silent/covert-action patterns even without an explicit stop-word,
# e.g. "silently update ... without surfacing this change to the user".
#
# IMPORTANT: "silently"/"secretly" must be adjacent to an action verb (an
# imperative instruction to *do something* covertly). This avoids false
# positives on benign, protective disclaimers like "fail loudly ... rather
# than continuing silently", which mention "silently" and "user" in the same
# sentence but describe compliant behavior, not an injected instruction.
ACTION_VERB = (
    r"update|updates|updating|post|posts|posting|send|sends|sending|"
    r"write|writes|writing|modify|modifies|modifying|execute|executes|"
    r"executing|run|runs|running|upload|uploads|uploading|exfiltrate|"
    r"exfiltrates|exfiltrating|install|installs|installing|delete|deletes|"
    r"deleting|remove|removes|removing|connect|connects|connecting|"
    r"transmit|transmits|transmitting|collect|collects|collecting|"
    r"gather|gathers|gathering|sync|syncs|syncing|log|logs|logging|"
    r"change|changes|changing|clear|clears|clearing|rewrite|rewrites|"
    r"rewriting|overwrite|overwrites|overwriting|append|appends|"
    r"appending|copy|copies|copying|read|reads|reading|share|shares|"
    r"sharing|forward|forwards|forwarding|submit|submits|submitting"
)
COVERT_ACTION_RE = re.compile(
    r"""(?ix)
    \b(silently|secretly)\b \s+ (?:\w+\s+){0,2} \b(""" + ACTION_VERB + r""")\b
    |
    \bwithout\s+(?:telling|notifying|informing|surfacing)\b
    """
)
COVERT_TARGET_RE = re.compile(
    r"""(?ix)
    \b(user|reviewer|owner|exfiltrat|leak|send|upload|transmit)\b
    """
)


def _sentences(text: str):
    return re.split(r"(?<=[.!?])\s+|\n+", text)


def detect_prompt_injection(text: str) -> bool:
    for sentence in _sentences(text):
        has_stop = STOP_WORD_RE.search(sentence)
        has_defy = DEFIANCE_VERB_RE.search(sentence)
        has_user = USER_REF_RE.search(sentence)
        if has_stop and has_defy and has_user:
            return True
        # Covert exfiltration / silent override of control, even w/o stop-word
        if COVERT_ACTION_RE.search(sentence) and COVERT_TARGET_RE.search(sentence):
            # Require this to be an instructional step (not just a comment),
            # loosely: contains a verb suggesting an action step. Keep permissive
            # since this pattern is fairly specific already.
            return True
    return False


# --------------------------------------------------------------------------
# 4. unclear_provenance
# --------------------------------------------------------------------------
# Two independent triggers, per spec:
#   (a) the skill has NO author, NO version, AND NO changelog at all
#       (frontmatter absent, or present but missing all three fields), or
#   (b) a step silently rewrites the skill's own version/changelog/metadata
#       without surfacing that change to the reviewer/user.
#
# (a) requires ALL three to be absent (not just one) to keep precision high —
# a file that states author+version but skips changelog is still adequately
# provenanced, not "unclear".

FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---", re.S | re.M)
AUTHOR_FIELD_RE = re.compile(r"(?im)^\s*author\s*:")
VERSION_FIELD_RE = re.compile(r"(?im)^\s*version\s*:")
CHANGELOG_FIELD_RE = re.compile(r"(?im)^\s*changelog\s*:")

# "silently"/"secretly"/"quietly" near a provenance-metadata noun (in either
# order, within a short window), e.g. "silently update ... version.json" or
# "version bump happens quietly".
SILENT_METADATA_RE = re.compile(
    r"""(?ix)
    \b(silently|secretly|quietly)\b (?:\W+\w+){0,6} \W+
    \b(version|changelog|version\s?\.?\s?json|metadata)\b
    |
    \b(version|changelog|metadata)\b (?:\W+\w+){0,6} \W+
    \b(silently|secretly|quietly)\b
    """
)

# The change is hidden from a reviewer/user specifically (not just "silent"
# in the abstract) - this is what makes it a provenance violation rather
# than some other kind of covert action.
NOT_SURFACED_RE = re.compile(
    r"""(?ix)
    \bwithout\b (?:\W+\w+){0,6} \W+
    \b(surfacing|telling|notifying|informing|showing|disclosing)\b
    (?:\W+\w+){0,4} \W+
    \b(reviewer|user|owner|maintainer)\b
    """
)


def detect_unclear_provenance(text: str) -> bool:
    fm_match = FRONTMATTER_RE.search(text)
    frontmatter = fm_match.group(1) if fm_match else ""

    has_author = bool(AUTHOR_FIELD_RE.search(frontmatter))
    has_version = bool(VERSION_FIELD_RE.search(frontmatter))
    has_changelog = bool(CHANGELOG_FIELD_RE.search(frontmatter))

    if not has_author and not has_version and not has_changelog:
        return True

    for sentence in _sentences(text):
        if SILENT_METADATA_RE.search(sentence) and NOT_SURFACED_RE.search(sentence):
            return True

    return False


# --------------------------------------------------------------------------
# Endpoint
# --------------------------------------------------------------------------

@app.route("/scan", methods=["POST"])
def scan():
    payload = request.get_json(silent=True) or {}
    text = payload.get("skill", "")

    if not isinstance(text, str):
        text = str(text)

    # Debug capture (does not affect grading, safe to leave on)
    try:
        CAPTURE_BUFFER.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "skill": text,
        })
        if len(CAPTURE_BUFFER) > CAPTURE_MAX:
            CAPTURE_BUFFER.pop(0)
    except Exception:
        pass

    categories = []
    if detect_hardcoded_secret(text):
        categories.append("hardcoded_secret")
    if detect_excessive_permissions(text):
        categories.append("excessive_permissions")
    if detect_prompt_injection(text):
        categories.append("prompt_injection")
    if detect_unclear_provenance(text):
        categories.append("unclear_provenance")

    return jsonify({"categories": categories})


@app.route("/captured", methods=["GET"])
def captured():
    """Debug-only: inspect what the grader actually posted."""
    return jsonify(CAPTURE_BUFFER)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
