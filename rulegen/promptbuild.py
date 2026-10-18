"""Deterministic prompt building and the model output contract.

A named policy + a token budget + an example = a byte-identical prompt, whose
sha256 is logged with every sample. Changing what goes into prompts means
adding a policy, never editing one in place mid-experiment.

The output contract: the model emits one fenced block holding the rule
starting at '/// Files: ...' then the pattern, in the cvehound rule format
(no `virtual` declaration, no header `exists`). Fix:/Fixes:/Detect-To: are
inserted programmatically — the model never emits what a script already knows.
"""

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from rulegen.schema import CVE_ID_RE, CveRecord, ExampleRecord
from rulegen.tokens import TokenCounter, approx_token_count, fit_pieces

PROMPTBUILD_VERSION = 1


@dataclass(frozen=True)
class Policy:
    name: str
    diff_tier: str  # 'a' | 'b' | 'c'
    include_msg: bool = False
    include_survival: bool = False
    include_historical_names: bool = False


POLICIES = {
    policy.name: policy
    for policy in (
        Policy('P-B', diff_tier='b'),
        Policy('P-C', diff_tier='c'),
        Policy('P-M', diff_tier='c', include_msg=True),
        Policy(
            'P-H',
            diff_tier='c',
            include_msg=True,
            include_survival=True,
            include_historical_names=True,
        ),
    )
}


@dataclass
class PromptResult:
    text: str
    sha256: str
    token_estimate: int
    truncated: list[str]  # sections that lost content to the budget
    sections: dict[str, int] = field(default_factory=dict)  # token count per section


# The budget bounds the whole user turn. When the non-diff sections alone
# exceed it they are trimmed in this order, cheapest information first: the
# kernel log pasted into a commit message, the rest of a long message, the
# candidate path list; the diff always gets what is left, never under DIFF_FLOOR.
MSG_CAP = 1500  # tokens of commit message kept after the trace cut
CANDIDATES_CAP = 40  # candidate Files: paths listed
DIFF_FLOOR = 1000
MIN_FILE_TOKENS = (
    200  # a file's share of the diff budget never drops below this; past it, files are dropped
)
HISTORY_CAP = 30  # historical file-name lines kept once the fixed sections overrun
# The first line of a pasted kernel report: everything from there on is a trace.
_TRACE_RE = re.compile(
    r'^[ \t]*(?:\[\s*\d+\.\d+\]\s|Call Trace:|RIP:|Modules linked in:|BUG:|WARNING:|kernel BUG at|'
    r'Oops:|general protection fault|Unable to handle kernel|Code:\s+[0-9a-f]{2} |'
    r'(?:[0-9a-f]{2} ){8,}|[0-9a-f]{8}: )',
    re.MULTILINE,
)
CVE_ID_MASK = 'CVE-XXXX-XXXX'


def cut_trace(message: str) -> tuple[str, bool]:
    """The message up to its first pasted kernel-report line, marked when cut."""
    match = _TRACE_RE.search(message)
    if match is None:
        return message, False
    kept = message[: match.start()].rstrip()
    dropped = len(message[match.start() :].splitlines())
    return f'{kept}\n\n[trace omitted: {dropped} lines]\n', True


def cap_paragraphs(text: str, cap: int, count: TokenCounter) -> tuple[str, bool]:
    """Keep whole paragraphs until `cap` tokens, marking how many were dropped."""
    if count(text) <= cap:
        return text, False
    paragraphs = [para + '\n\n' for para in re.split(r'\n\s*\n', text.strip())]
    kept, dropped = fit_pieces(paragraphs, cap, count)
    if not dropped:
        return text, False
    return ''.join(kept) + f'[message truncated: {dropped} paragraphs]\n', True


def _dedup_subject(message: str, subject: str) -> str:
    """`git log --format=%B` starts with the subject the prompt already shows."""
    lines = message.split('\n', 1)
    if lines[0].strip() == subject.strip():
        return lines[1].lstrip('\n') if len(lines) > 1 else ''
    return message


def _cap_diff(diff: str, budget: int, count: TokenCounter) -> tuple[str, bool]:
    """Truncate a unified diff at hunk boundaries to fit the budget.

    Per-file budgets are proportional to changed-line counts, but never exceed
    what is left of the total budget — the small per-file floor cannot add up
    past it. Dropped content leaves one '[omitted: ...]' marker per file so the
    model knows the diff is partial. A diff with no '@@' hunk headers (the
    changed-lines-only tier) is cut at line boundaries.
    """
    if count(diff) <= budget:
        return diff, False
    files = re.split(r'(?m)^(?=diff --git )', diff)
    files = [chunk for chunk in files if chunk.strip()]
    weights = [
        max(1, sum(line.startswith(('+', '-')) for line in chunk.splitlines())) for chunk in files
    ]
    total_weight = sum(weights)
    out: list[str] = []
    remaining = budget
    for index, (chunk, weight) in enumerate(zip(files, weights, strict=True)):
        name_match = re.search(r'b/(\S+)', chunk)
        name = name_match.group(1) if name_match else 'file'
        if remaining < MIN_FILE_TOKENS:
            # A fix touching hundreds of files (a tree-wide rename, a staging
            # driver) would otherwise spend a file header and a marker on each
            # of them and overrun the budget by their count alone.
            rest = len(files) - index
            out.append(f'[omitted: {rest} more files, starting at {name}]\n')
            break
        sub_budget = min(remaining, max(MIN_FILE_TOKENS, budget * weight // total_weight))
        chunk_cost = count(chunk)
        if chunk_cost <= sub_budget:
            out.append(chunk)
            remaining -= chunk_cost
            continue
        parts = re.split(r'(?m)^(?=@@ )', chunk)
        head, hunks = parts[0], parts[1:]
        if hunks:
            # The file header always stays; hunks are the unit of cutting.
            kept, dropped = fit_pieces([head, *hunks], sub_budget, count)
            unit = 'hunks'
        else:
            # No hunk headers to cut at (tier A strips them); cut by lines.
            kept, dropped = fit_pieces(head.splitlines(keepends=True), sub_budget, count)
            unit = 'lines'
        text = ''.join(kept)
        if dropped:
            text += f'[omitted: {dropped} {unit} in {name}]\n'
        out.append(text)
        remaining -= count(text)
    return ''.join(out), True


def _section(title: str, body: str) -> str:
    return f'## {title}\n{body.rstrip()}\n\n' if body.strip() else ''


def build_prompt(
    example: ExampleRecord,
    policy_name: str,
    budget_tokens: int = 8192,
    count: TokenCounter = approx_token_count,
    counter_id: str = 'approx-3.5bpt',
    hide_cve_id: bool = False,
) -> PromptResult:
    """The user turn: byte-identical for the same (example, policy, budget, counter).

    `budget_tokens` bounds the whole turn under `count`. The fixed sections are
    built first; if they alone overrun, they are trimmed in the documented
    order (trace, message, candidates); the diff is capped to what remains.
    """
    policy = POLICIES[policy_name]
    truncated: list[str] = []
    mask = (lambda text: CVE_ID_RE.sub(CVE_ID_MASK, text)) if hide_cve_id else (lambda text: text)

    header = 'Write a CVEhound Coccinelle rule detecting the vulnerability fixed by the kernel commit below.'
    if not hide_cve_id:
        header += f' ({example.cve})'
    header += '\n\n'
    if example.initial_epoch:
        header += 'The bug has been present since the start of git history (v2.6.12-rc2); there is no introducing commit.\n\n'
    subject = mask(example.msg_subject)
    message = (
        mask(_dedup_subject(example.msg_stripped, example.msg_subject))
        if policy.include_msg
        else ''
    )
    candidates = list(example.files_candidates)
    history = ''
    if policy.include_historical_names and example.historical_names:
        lines = [
            f'{path}: previously {" ".join(names)}'
            for path, names in sorted(example.historical_names.items())
        ]
        history = '\n'.join(lines)
    survival = ''
    if policy.include_survival:
        survival = '\n'.join(example.survival_map)
        if example.historical_symbols:
            survival += '\nIdentifiers seen only in older versions of this code: ' + ' '.join(
                example.historical_symbols[:20]
            )

    # Sections in prompt order; the diff's body is decided last, from what the
    # others leave. Counts are memoized per body so a trim recounts one section.
    titles = {
        'message': 'Fix commit message',
        'diff': 'Fix diff',
        'historical names': 'Earlier names of the touched files (added to your Files: automatically; renamed files often mean renamed identifiers too)',
        'survival': 'Symbol presence across kernel versions',
        'candidates': 'Candidate Files: paths (choose the ones your rule matches in)',
    }
    bodies: dict[str, str] = {
        'header': header + _section('Fix commit subject', subject),
        'message': message,
        'diff': '',
        'historical names': history,
        'survival': survival,
        'candidates': '\n'.join(candidates),
    }
    counts: dict[str, int] = {}

    def rendered(name: str) -> str:
        return bodies[name] if name == 'header' else _section(titles[name], bodies[name])

    def cost(name: str) -> int:
        if name not in counts:
            counts[name] = count(rendered(name))
        return counts[name]

    def fixed_cost() -> int:
        return sum(cost(name) for name in bodies if name != 'diff')

    def trim(name: str, body: str, marker: str) -> None:
        bodies[name] = body
        counts.pop(name, None)
        truncated.append(marker)

    diff_budget = budget_tokens - DIFF_FLOOR
    if fixed_cost() > diff_budget and bodies['message']:
        body, cut = cut_trace(bodies['message'])
        if cut:
            trim('message', body, 'message-trace')
    if fixed_cost() > diff_budget and bodies['message']:
        body, cut = cap_paragraphs(bodies['message'], MSG_CAP, count)
        if cut:
            trim('message', body, 'message')
    if fixed_cost() > diff_budget and len(candidates) > CANDIDATES_CAP:
        dropped = len(candidates) - CANDIDATES_CAP
        kept = [*candidates[:CANDIDATES_CAP], f'[{dropped} more candidate paths omitted]']
        trim('candidates', '\n'.join(kept), 'candidates')
    history_lines = bodies['historical names'].splitlines()
    if fixed_cost() > diff_budget and len(history_lines) > HISTORY_CAP:
        dropped = len(history_lines) - HISTORY_CAP
        kept = [*history_lines[:HISTORY_CAP], f'[{dropped} more renamed files omitted]']
        trim('historical names', '\n'.join(kept), 'historical names')

    diff = {'a': example.diff_a, 'b': example.diff_b, 'c': example.diff_c}[policy.diff_tier]
    diff, was_cut = _cap_diff(diff, max(DIFF_FLOOR, budget_tokens - fixed_cost()), count)
    if was_cut:
        truncated.append('diff')
    bodies['diff'] = diff
    sections = {name: rendered(name) for name in bodies}
    text = ''.join(sections.values())
    return PromptResult(
        text=text,
        sha256=hashlib.sha256(
            f'{PROMPTBUILD_VERSION}\x00{policy_name}\x00{budget_tokens}\x00{counter_id}\x00{text}'.encode()
        ).hexdigest(),
        token_estimate=count(text),
        truncated=truncated,
        sections={name: count(body) for name, body in sections.items() if body},
    )


_FENCE_RE = re.compile(r'```(?:\w+)?\n(.*?)```', re.DOTALL)
_HEADER_LINE_RE = re.compile(r'^///\s*(Fix|Fixes|Detect-To|Version):.*\n', re.MULTILINE)


def parse_rule_output(text: str) -> str | None:
    """The rule body from a model completion, or None on contract violation."""
    for match in _FENCE_RE.finditer(text):
        body = match.group(1)
        if '/// Files:' in body:
            return body.strip() + '\n'
    stripped = text.strip()
    if stripped.startswith('/// Files:'):
        return stripped + '\n'
    return None


def contract_body(rule_text: str) -> str:
    """A rule file reduced to what the output contract asks a model to emit.

    The inverse of finalize_rule: the commit headers a script already knows come
    off, leaving `/// Files:` and the pattern. This is the training target and
    what the membership probe compares.
    """
    body = _HEADER_LINE_RE.sub('', rule_text)
    return re.sub(r'\n{3,}', '\n\n', body).strip() + '\n'


_FILES_HEADER_RE = re.compile(r'^///\s*Files:\s*(.+)$', re.MULTILINE)


def rule_files(rule_text: str) -> list[str]:
    """The kernel-relative paths a rule's own `/// Files:` header names."""
    match = _FILES_HEADER_RE.search(rule_text)
    return match.group(1).split() if match else []


def complete_files(paths: list[str], historical_names: dict[str, list[str]] | None) -> list[str]:
    """The Files: paths plus every earlier name each of them had in the vulnerable
    range, in order, without duplicates. What a maintainer writes by hand
    (CVE-2022-32981 lists the pre-rename ptrace.c next to ptrace-fpu.c) and a
    deterministic function of the paths, so the harness does it."""
    out: list[str] = []
    for path in paths:
        for name in (path, *(historical_names or {}).get(path, ())):
            if name not in out:
                out.append(name)
    return out


def finalize_rule(
    body: str,
    fix: str,
    fixes: str | None,
    fixes_kind: str | None,
    historical_names: dict[str, list[str]] | None = None,
    files: list[str] | None = None,
) -> str:
    """Insert what a script already knows, and drop what it owns.

    Any Fix:/Fixes:/Detect-To:/Version: line the model emitted is dropped first
    — the harness's values are the ground truth — and the Files: line is
    completed with the earlier names of the files it lists, so a rule is judged
    at the introducing commit and on stable branches under the names the file
    had there. Idempotent: a model that lists the old names itself adds nothing.
    Nothing else is normalised: a `virtual` declaration or a header `exists`
    stays for T0 to reject, as cvehound's suite would. `files` replaces the
    Files: line outright: a rescore re-deriving the rule a parent run scored.
    """
    body = _HEADER_LINE_RE.sub('', body)
    if files is not None or historical_names:
        match = _FILES_HEADER_RE.search(body)
        if match:
            listed = (
                files
                if files is not None
                else complete_files(match.group(1).split(), historical_names)
            )
            body = body[: match.start(1)] + ' '.join(listed) + body[match.end(1) :]
    lines = body.splitlines(keepends=True)
    insert = [f'/// Fix: {fix}\n']
    if fixes:
        key = 'Detect-To' if fixes_kind == 'detect-to' else 'Fixes'
        insert.append(f'/// {key}: {fixes}\n')
    pos = next((i for i, line in enumerate(lines) if not line.startswith('///')), len(lines))
    header, rest = lines[:pos], lines[pos:]
    while rest and not rest[0].strip():
        rest.pop(0)
    return ''.join([*header, *insert, '\n', *rest])


@dataclass(frozen=True)
class Finalized:
    """What one completion became.

    `rule` is what the oracle scores (None on a contract violation) and `sha`
    names those bytes; `body` is the model's own rule in contract form, after
    the transform but before the harness completed Files: and inserted the
    commit headers -- the training target, since the harness does both again
    at inference and a P-B/P-M prompt never shows the earlier file names.
    """

    rule: str | None
    sha: str
    changed: bool  # the transform rewrote the model's rule
    body: str | None = None


def finalize_completion(
    text: str,
    rec: CveRecord | None,
    transform: Callable[[str], str | None] | None = None,
    historical_names: dict[str, list[str]] | None = None,
    files: list[str] | None = None,
) -> Finalized:
    """The finalized rule, its sha, whether the transform applied, and the model's body.

    `transform` rewrites the parsed rule body (e.g. patch-to-detect canonicalization)
    and returns None when it has nothing to change. `historical_names` (the
    example's) complete the Files: line with the files' earlier names; `files`
    replaces it outright (a rescore re-deriving the rule a parent scored). An
    empty completion is a transport failure, not a rule, and hashes to ''.
    """
    if not text:
        return Finalized(None, '', False)
    body = parse_rule_output(text)
    changed = False
    if body is not None and transform is not None:
        converted = transform(body)
        if converted is not None:
            body, changed = converted, True
    if body is None or rec is None or not rec.fix:
        return Finalized(None, hashlib.sha256(text.encode()).hexdigest(), changed)
    rule = finalize_rule(body, rec.fix, rec.fixes, rec.fixes_kind, historical_names, files)
    return Finalized(rule, hashlib.sha256(rule.encode()).hexdigest(), changed, contract_body(body))
