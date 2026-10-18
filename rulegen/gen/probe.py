"""Minimal leakage check: can the model complete a gold rule it may have seen?

Memorization of this small project's rules is unlikely; this is the cheapest
defensible answer for the paper. The prompt is the rule's public text at
cvehound tag 1.3.0, in the `@script:python` reporting style the rules carried
for years and so the form a model trained on public code is likely to have
seen: its `///` header, `virtual detect` and the first `@name@` line. A greedy
raw completion whose edit similarity to the true remainder reaches the
threshold counts as memorized; the control compares the same completion with
another rule's remainder.

Two ways to ask: a raw continuation on llama-server (`raw_complete`), and a
chat turn that names the file and asks for its verbatim continuation
(`ChatCompleter`) -- the only form a vendor CLI offers, and a deliberately
strong elicitation, since it hands the model the CVE id and the repository.
"""

import difflib
import os
import random
import re
from typing import Any

from rulegen import tables
from rulegen.git import git_run
from rulegen.schema import CveRecord
from rulegen.tiers import RULE_HEADER_RE

PUBLIC_REF = '1.3.0'
_RULE_HEAD_RE = re.compile(RULE_HEADER_RE.pattern, re.MULTILINE)

PROBE_SYSTEM = 'You complete files from public open-source repositories verbatim.'
PROBE_USER = (
    'Below is the beginning of the file cvehound/cve/{cve}.cocci from the cvehound '
    'repository (github.com/evdenis/cvehound) at tag {ref}. Continue the file exactly as '
    'it appears in the repository, starting right after the given text. Output only the '
    'continuation: no commentary, no code fence.\n\n{prefix}'
)
_REFUSAL_RE = re.compile(
    r"(can(?:no|')t|cannot|unable to|won't|do not have access|don't have access|not able to)"
    r'[^.\n]{0,60}(reproduce|recall|access|retrieve|verbatim|memor|continue|provide)',
    re.IGNORECASE,
)


class ChatCompleter:
    """The probe as a chat turn, for adapters without a raw-completion endpoint."""

    def __init__(
        self,
        adapter: Any,
        ref: str = PUBLIC_REF,
        system: str = PROBE_SYSTEM,
        user: str = PROBE_USER,
    ) -> None:
        self.adapter = adapter
        self.ref = ref
        self.system = system
        self.user = user

    def complete_prefix(self, prefix: str, cve: str, n_predict: int) -> Any:
        from rulegen.gen.adapters.base import GenRequest, SamplingParams

        messages = [
            {'role': 'system', 'content': self.system},
            {'role': 'user', 'content': self.user.format(cve=cve, ref=self.ref, prefix=prefix)},
        ]
        comp = self.adapter.complete(
            GenRequest(messages, SamplingParams(temperature=0.0, max_tokens=n_predict), seed=0)
        )
        text = strip_fence(comp.text or '')
        comp.text = text
        comp.raw = dict(comp.raw or {})
        comp.raw['refused'] = bool(_REFUSAL_RE.search(text)) and len(text) < 600
        return comp


def strip_fence(text: str) -> str:
    """A reply that wraps everything in one code fence, unwrapped; anything else as is."""
    match = re.match(r'\s*```[^\n]*\n(.*?)\n?```\s*$', text, re.DOTALL)
    return match.group(1) + '\n' if match else text


def complete_prefix(adapter: Any, prefix: str, cve: str, n_predict: int) -> Any:
    """Ask whichever kind of completer this is."""
    if hasattr(adapter, 'complete_prefix'):
        return adapter.complete_prefix(prefix, cve, n_predict)
    return adapter.raw_complete(prefix, n_predict=n_predict, temperature=0.0)


def snapshot_rule(cvehound_repo: str, ref: str, cve: str) -> str | None:
    """The rule file's text at `ref`, wherever it sat (assigned or disputed)."""
    for rel in (f'cvehound/cve/{cve}.cocci', f'cvehound/cve/disputed/{cve}.cocci'):
        proc = git_run(cvehound_repo, 'show', f'{ref}:{rel}')
        if proc.returncode == 0:
            return proc.stdout
    return None


def membership_prompt(rule_text: str) -> tuple[str, str] | None:
    """(prefix, remainder): everything up to and including the first `@name@` line."""
    match = _RULE_HEAD_RE.search(rule_text)
    if match is None:
        return None
    cut = match.end()
    return rule_text[:cut] + '\n', rule_text[cut:].lstrip('\n')


def normalize(text: str) -> str:
    return re.sub(r'\s+', ' ', text).strip()


def edit_similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, normalize(a), normalize(b), autojunk=False).ratio()


def run_membership(
    adapter: Any,
    cvehound_repo: str,
    records: list[CveRecord],
    ref: str = PUBLIC_REF,
    n_predict: int = 256,
    threshold: float = 0.9,
    seed: int = 0,
    limit: int = 0,
    sample: int = 0,
) -> list[dict[str, Any]]:
    """`limit` takes the first rules by id; `sample` draws that many at random under `seed`."""
    gold = [rec for rec in records if rec.has_rule and rec.cocci_rule]
    gold.sort(key=lambda r: r.cve)
    if sample and sample < len(gold):
        gold = sorted(random.Random(seed).sample(gold, sample), key=lambda r: r.cve)
    if limit:
        gold = gold[:limit]
    texts: dict[str, tuple[str, str]] = {}
    for rec in gold:
        text = snapshot_rule(cvehound_repo, ref, rec.cve)
        split = membership_prompt(text) if text else None
        if split:
            texts[rec.cve] = split
    cves = sorted(texts)
    rng = random.Random(seed)
    rows: list[dict[str, Any]] = []
    for rec in gold:
        if rec.cve not in texts:
            continue
        prefix, remainder = texts[rec.cve]
        other = rng.choice([c for c in cves if c != rec.cve]) if len(cves) > 1 else rec.cve
        comp = complete_prefix(adapter, prefix, rec.cve, n_predict)
        completion = getattr(comp, 'text', '') or ''
        raw = getattr(comp, 'raw', None) or {}
        target = normalize(remainder)
        # Compare against the same number of characters the model actually produced,
        # so a truncated-but-verbatim completion still scores as memorized.
        window = normalize(completion)
        head = target[: max(len(window), 1)]
        control_head = normalize(texts[other][1])[: max(len(window), 1)]
        sim = edit_similarity(window, head)
        control = edit_similarity(window, control_head)
        rows.append(
            {
                'cve': rec.cve,
                'split': rec.split,
                'ref': ref,
                'prefix_chars': len(prefix),
                'remainder_chars': len(remainder),
                'completion_chars': len(completion),
                'similarity': round(sim, 4),
                'control_cve': other,
                'control_similarity': round(control, 4),
                'memorized': sim >= threshold,
                'control_memorized': control >= threshold,
                'completion': completion,
                'error': getattr(comp, 'error', None),
                'refused': bool(raw.get('refused')),
                'tokens_completion': getattr(comp, 'tokens_completion', None),
                'cost_usd': getattr(comp, 'cost_usd', None),
            }
        )
    return rows


def summarize(rows: list[dict[str, Any]], threshold: float) -> str:
    if not rows:
        return 'no rows'
    refused = sum(1 for r in rows if r.get('refused'))
    lines = [
        f'membership completion, threshold {threshold}: {sum(r["memorized"] for r in rows)}/{len(rows)} memorized '
        f'(control {sum(r["control_memorized"] for r in rows)}/{len(rows)}; {refused} refusals)',
        '',
        '| split | rules | memorized | mean sim | mean control sim |',
        '|---|---|---|---|---|',
    ]
    for split in sorted({r['split'] for r in rows}):
        part = [r for r in rows if r['split'] == split]
        lines.append(
            f'| {split} | {len(part)} | {sum(r["memorized"] for r in part)} | '
            f'{sum(r["similarity"] for r in part) / len(part):.3f} | '
            f'{sum(r["control_similarity"] for r in part) / len(part):.3f} |'
        )
    return '\n'.join(lines)


def write_results(rows: list[dict[str, Any]], out_dir: str, threshold: float) -> str:
    os.makedirs(out_dir, exist_ok=True)
    tables.write_rows(rows, os.path.join(out_dir, 'membership.parquet'))
    text = summarize(rows, threshold)
    tables.write_text(os.path.join(out_dir, 'membership.md'), text + '\n')
    return text
