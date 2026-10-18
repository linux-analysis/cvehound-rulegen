"""Context-tier classification of the gold rules.

For one gold `.cocci` rule, find the smallest git context window at its `Fix:`
commit whose text already contains every *literal* token the rule requires.
That is the input-design question for generation: a rule whose tokens are not
derivable from the fix commit cannot be written from the fix commit.

Tiers, evaluated over the rule's own `Files:` at `Fix`:

    A   the +/- payload of a -U0 diff
    B   the standard -U3 diff
    C   `git show -W` (whole enclosing functions)
    C2  C plus the full commit message
    D   the complete file contents at Fix~ and Fix
    E   none of the above -- the token lives in another file, another kernel
        version, or nowhere

"Literal" is the distinction that makes this measurement mean anything: a name
carried by a declared `identifier`/`expression`/... metavariable is a
placeholder and matches anything, so it costs no context, while a name declared
as `symbol`/`declarer name`/`iterator name` matches literally and does. Both
kinds look like plain identifiers in the rule body, so the declaration block has
to be parsed rather than regex-scanned.

`tokens.identifiers()` is deliberately not reused here: it has no notion of
metavariable declarations and a different stoplist. Its meaning is "identifiers
in this text" and it is shared with the survival map; this module needs
"identifiers this rule cannot match without".
"""

import json
import os
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from rulegen import shapes, tables
from rulegen.git import git, resolves
from rulegen.tokens import IDENT_RE
from rulegen.vocabulary import VOCABULARY

# Ordered from tightest to loosest; the first tier that covers every token wins.
TIER_ORDER = ('A', 'B', 'C', 'C2', 'D')
TIER_OUTSIDE = 'E'
TIER_NOSTAR = 'NOSTAR'  # rule has no literal token on any starred line
# Every class a rule can land in: the tiers, then outside them.
CLASSES = (*TIER_ORDER, TIER_OUTSIDE)
# The tier table under the data directory.
TIERS = 'tiers.parquet'

# Metavariable kinds whose declared names are placeholders (match anything).
# Longest first: the scan below strips the first kind that prefixes the
# declaration, and 'expression list' must win over 'expression'.
_PLACEHOLDER_KINDS = (
    'local idexpression',
    'fresh identifier',
    'expression list',
    'identifier list',
    'parameter list',
    'binary operator',
    'assignment operator',
    'unary operator',
    'idexpression',
    'identifier',
    'expression',
    'initializer',
    'statement',
    'attribute',
    'parameter',
    'constant',
    'position',
    'operator',
    'function',
    'typedef',
    'format',
    'field',
    'type',
)

# Metavariable kinds whose declared names match literally -- these are tokens.
_LITERAL_KINDS = (
    'declarer name',
    'iterator name',
    'attribute name',
    'declarer',
    'iterator',
    'symbol',
    'macro',
)

# Every declaration kind SmPL accepts, longest first: the one list any parser of
# a metavariable block should scan.
METAVAR_KINDS = tuple(sorted(_PLACEHOLDER_KINDS + _LITERAL_KINDS, key=len, reverse=True))

# Numeric literals first, or 0x1234ab leaves a bare 'ab'-style identifier behind.
_NUM_RE = re.compile(r'\b0[xX][0-9a-fA-F]+[uUlL]*|\b\d+[uUlL]*\b')
_STAR_RE = re.compile(r'^\s*\*(\s|$|[A-Za-z_(\\])')

# --- SmPL block structure -----------------------------------------------------
# The one definition of a rule header line ('@name@', never the '@@' that closes
# a metavariable block), for every module that walks SmPL blocks.
RULE_HEADER_RE = re.compile(r'^@[^@\n]*@\s*$')
# A position annotation on an identifier (`f@p(`, `x@p`).
POSITION_RE = re.compile(r'@[A-Za-z_]\w*\b')


def is_header(line: str) -> bool:
    return bool(RULE_HEADER_RE.match(line)) and line.strip() != '@@'


def next_header(lines: list[str], start: int) -> int:
    k = start
    while k < len(lines) and not is_header(lines[k]):
        k += 1
    return k


def blocks(lines: list[str]) -> list[tuple[int, int, int]]:
    """(header line, metavariable-closing `@@` line, end) per named rule block.

    The single walker: every pass slices what it needs out of these indices.
    An anonymous rule (`@@ ... @@`, no header) yields no block: parse_rule reads
    it, the block-wise passes (canon, wildcard_stars) do not.
    """
    out = []
    i = 0
    while i < len(lines):
        if is_header(lines[i]):
            j = i + 1
            while j < len(lines) and lines[j].strip() != '@@':
                j += 1
            k = next_header(lines, j + 1)
            out.append((i, j, k))
            i = k
        else:
            i += 1
    return out


# Words a rule body can contain that never constrain which files spatch opens:
# SmPL pattern keywords, C keywords, and the width-typedef vocabulary that is in
# every translation unit. Metavariable *kind* words (`identifier`, `statement`,
# ...) are deliberately absent: they are consumed by the declaration parser and
# never reach a pattern line, so stoplisting them would wrongly drop real field
# names like `->name`, `->list` or `->function`.
_EXCLUDED = frozenset(
    """
    when any exists forall depends virtual detect disable using strict
    auto break case char const continue default do double else enum extern
    float for goto if inline int long register restrict return short signed
    sizeof static struct switch typedef union unsigned void volatile while
    NULL true false bool asm define
    u16 u32 u64 s16 s32 s64
    size_t ssize_t uint8_t uint16_t uint32_t uint64_t int8_t int16_t
    int32_t int64_t
    """.split()  # noqa: SIM905
)
# What never counts as a literal token: markup and C, plus kernel vocabulary.
_DROP = _EXCLUDED | VOCABULARY


@dataclass
class TierRecord:
    """One rule's context-tier verdict."""

    cve: str
    rule_path: str
    fix: str
    files: list[str] = field(default_factory=list)
    cls: str = TIER_OUTSIDE  # tier for all literal tokens
    scls: str = TIER_NOSTAR  # tier for starred-line tokens only
    ntok: int = 0
    nstar: int = 0
    missing: dict[str, list[str]] = field(default_factory=dict)  # tier -> tokens absent
    fallback: bool = False  # the Files:-restricted diff was empty; used the whole commit
    unresolved: bool = False  # Fix: does not resolve in this kernel


def _strip_markup(line):
    """Drop cocci markup so only the C-ish payload of a pattern line is tokenized."""
    line = re.sub(r'^\s*[*\-+]', '', line)
    for token in ('\\(', '\\|', '\\)', '<+...', '...+>', '<...', '...>', '...'):
        line = line.replace(token, ' ')
    line = re.sub(r'\bwhen\s*(!=|==)', ' ', line)
    line = re.sub(r'\bwhen\s+(any|forall|strict|exists)\b', ' ', line)
    return _NUM_RE.sub(' ', line)


def _tokens(lines, placeholders):
    return {
        tok
        for line in lines
        for tok in IDENT_RE.findall(_strip_markup(line))
        if tok not in _DROP and tok not in placeholders
    }


def parse_rule(text):
    """(placeholder names, literal metavariable names, pattern lines, starred lines).

    Walks the rule as a state machine because `@name@ ... @@` delimits the
    declaration block, and the same identifier means different things on the two
    sides of it.
    """
    placeholders: set[str] = set()
    literals: set[str] = set()
    pattern: list[str] = []
    starred: list[str] = []
    mode = 'none'
    in_block_comment = False

    for raw in text.splitlines():
        if raw.startswith('///'):
            continue
        line = raw.strip()
        if line == '@@':
            # An anonymous rule opens with `@@` as well as closing with it, so the
            # first one opens a declaration section rather than a pattern: without
            # this its metavariables are read as pattern text and every one of them
            # counts as a literal name the rule requires.
            mode = 'pattern' if mode == 'declarations' else 'declarations'
            continue
        if RULE_HEADER_RE.match(line):
            mode = 'declarations'
            continue

        if mode == 'declarations':
            decl = line.rstrip(';').strip()
            kind = names_part = None
            for candidate in (*_LITERAL_KINDS, *_PLACEHOLDER_KINDS):
                if not decl.startswith(candidate):
                    continue
                rest = decl[len(candidate) :].strip()
                # `identifier list;` declares a metavariable named `list`, not an
                # empty `identifier list` declaration. A multi-word kind only wins
                # when names actually follow it.
                if not rest:
                    continue
                kind, names_part = candidate, rest
                break
            if kind is None:
                continue
            # `identifier c.f;` inherits f from rule c: in this rule it is the placeholder f.
            names = [
                re.sub(r'[^A-Za-z0-9_]', '', part.split('.')[-1]) for part in names_part.split(',')
            ]
            target = literals if kind in _LITERAL_KINDS else placeholders
            target.update(name for name in names if name)
        elif mode == 'pattern':
            if line.startswith('//'):
                continue
            body = raw
            if in_block_comment:
                if '*/' in body:
                    body = body.split('*/', 1)[1]
                    in_block_comment = False
                else:
                    continue
            body = re.sub(r'/\*.*?\*/', ' ', body)
            if '/*' in body:
                body = body.split('/*', 1)[0]
                in_block_comment = True
            # A trailing // comment, but never a leading one: '*' + '//' cannot
            # both start the line, and body[0] may legitimately be '/'.
            if '//' in body[1:]:
                body = body[:1] + body[1:].split('//', 1)[0]
            pattern.append(body)
            if _STAR_RE.match(raw):
                starred.append(body)

    return placeholders, literals, pattern, starred


def _literal_sets(parsed):
    """literal_tokens() over an already parsed rule."""
    placeholders, literals, pattern, starred = parsed
    return (
        _tokens(pattern, placeholders) | (literals - VOCABULARY),
        _tokens(starred, placeholders),
    )


def literal_tokens(text):
    """(all literal tokens the rule requires, those on its starred lines).

    Names a kernel programmer already has are dropped -- see rulegen/vocabulary.py
    for the gate: the tier measurement is about context a rule author would have
    to look up, and a token like `memcpy` is not that.
    """
    return _literal_sets(parse_rule(text))


def has_literal_anchor(text):
    """Does the rule name anything of the vulnerable code at all?

    A rule whose every identifier is a metavariable or common kernel vocabulary
    says nothing about this bug; one literal name anywhere -- the function it is
    anchored in, a field, a macro -- is what makes a report mean something. The
    starred lines alone are not the test: `foo(...) { ... * return -1; }` is a
    legitimate shape (many gold rules star only vocabulary) and `foo` is its
    anchor.
    """
    return bool(literal_tokens(text)[0])


# A call whose callee is not a field (`p->fn(x)` is a function pointer field,
# which a metavariable may legitimately stand for) or a keyword.
_CALLEE_RE = re.compile(r'(?<![\w.>])([A-Za-z_]\w*)\s*\(')


def wildcard_stars(text):
    """Metavariables standing where a name belongs on a report: the callee of a
    starred call, or the function head that anchors a reporting rule whose block
    names nothing literal.

    This is a degeneration -- a named call turned into `f(...)` -- and no oracle
    leg can see it: the rule still fires and stays silent in all the same
    places. Gold rules never do it once `@pos` annotations are stripped; a
    metavariable *field* on a starred line (`skey->keylen`) is a renamed field
    and is not a wildcard.
    Returns the offending metavariable names, one block at a time.
    """
    lines = [
        line if RULE_HEADER_RE.match(line) else POSITION_RE.sub('', line)
        for line in text.split('\n')
    ]
    found: list[str] = []
    for head, _meta_end, end in blocks(lines):
        parsed = parse_rule('\n'.join(lines[head:end]))
        placeholders, _literals, pattern, starred = parsed
        if not starred:
            continue
        found += [
            callee
            for line in starred
            for callee in _CALLEE_RE.findall(_strip_markup(line))
            if callee in placeholders
        ]
        first = next((line for line in pattern if line.strip()), '')
        anchor = shapes.function_head(first)  # the head test canon and the baseline share
        if anchor in placeholders and not _literal_sets(parsed)[0]:
            found.append(anchor)
    return list(dict.fromkeys(found))


def text_terms(text):
    """(anchored, wildcards): what the text says about the bug -- the reward's
    two text terms (oracle T0) and the audit's trivial_echo / wildcard_star."""
    return has_literal_anchor(text), wildcard_stars(text)


def _show(kernel, *args):
    """A git read whose failure means "nothing here" (a path missing at a revision)."""
    return git(kernel, *args, ok=None)


def _changed_lines(diff_u0):
    """The +/- payload of a -U0 diff, prefix stripped, file headers dropped."""
    return '\n'.join(
        line[1:]
        for line in diff_u0.splitlines()
        if line[:1] in '+-' and not line.startswith(('+++', '---'))
    )


def tier_texts(kernel, fix, files):
    """({tier: text}, fallback). Empty Files: scope falls back to the whole commit."""
    scope = ['--', *files] if files else []
    diff_b = _show(kernel, 'show', '--format=', fix, *scope)
    fallback = not diff_b.strip() and bool(files)
    if fallback:
        scope = []
        diff_b = _show(kernel, 'show', '--format=', fix)

    diff_a = _changed_lines(_show(kernel, 'show', '--format=', '-U0', fix, *scope))
    diff_c = _show(kernel, 'show', '--format=', '-W', fix, *scope)
    message = _show(kernel, 'log', '-1', '--format=%B', fix)

    blobs = []
    for path in files:
        for rev in (f'{fix}~', fix):
            blob = _show(kernel, 'show', f'{rev}:{path}')
            if blob:
                blobs.append(blob)
    full = '\n'.join(blobs)

    return {
        'A': diff_a,
        'B': diff_b,
        'C': diff_c,
        'C2': diff_c + '\n' + message,
        'D': full,
        # Not a tier of its own: the report of what a class-E rule is missing
        # should not blame a token the commit message does carry.
        'D2': full + '\n' + message,
    }, fallback


def absent_tokens(tokens: Iterable[str], text):
    """Which of `tokens` the text does not contain, on a word boundary."""
    return sorted(tok for tok in tokens if not re.search(r'\b' + re.escape(tok) + r'\b', text))


def _first_covering(tokens, texts):
    for tier in TIER_ORDER:
        if not absent_tokens(tokens, texts[tier]):
            return tier
    return TIER_OUTSIDE


def classify_rule(kernel, cve, rule_path, fix, files):
    """Classify one rule. `fix`/`files` come from the rule's own header."""
    with open(rule_path, errors='replace') as fh:
        text = fh.read()
    all_tokens, star_tokens = literal_tokens(text)
    rec = TierRecord(
        cve=cve,
        rule_path=rule_path,
        fix=fix,
        files=list(files),
        ntok=len(all_tokens),
        nstar=len(star_tokens),
    )
    if not resolves(kernel, fix):
        rec.unresolved = True
        return rec

    texts, rec.fallback = tier_texts(kernel, fix, files)
    rec.cls = _first_covering(all_tokens, texts)
    rec.scls = TIER_NOSTAR if not star_tokens else _first_covering(star_tokens, texts)
    rec.missing = {tier: absent_tokens(all_tokens, texts[tier]) for tier in (*TIER_ORDER, 'D2')}
    rec.missing['star_D2'] = absent_tokens(star_tokens, texts['D2'])
    return rec


def classify_corpus(kernel, records, jobs=1):
    """Classify every gold .cocci rule in `records` (corpus CveRecords)."""
    from concurrent.futures import ThreadPoolExecutor

    gold = [rec for rec in records if rec.cocci_rule and rec.fix and rec.files_gold]

    def work(rec):
        return classify_rule(kernel, rec.cve, rec.rule_path, rec.fix, rec.files_gold)

    with ThreadPoolExecutor(max(1, jobs)) as pool:
        return sorted(pool.map(work, gold), key=lambda r: r.cve)


def load_tiers(path):
    """The rows save_tiers wrote, with the JSON columns decoded."""
    rows = tables.read_rows(path)
    for row in rows:
        if isinstance(row.get('missing'), str):
            row['missing'] = json.loads(row['missing'])
    return rows


def load_classes(data_dir, missing_ok=True):
    """cve -> context class from the tier table; {} when it has not been built, unless
    the caller cannot do without it."""
    path = os.path.join(data_dir, TIERS)
    if missing_ok and not os.path.exists(path):
        return {}
    return {row['cve']: row['cls'] for row in load_tiers(path)}


def save_tiers(records, path):
    import dataclasses

    rows = []
    for rec in records:
        row = dataclasses.asdict(rec)
        row['missing'] = json.dumps(row['missing'], sort_keys=True)
        rows.append(row)
    tables.write_rows(rows, path)


def summarize(records):
    """{class: count} over `cls`, in tier order."""
    counts = Counter(rec.cls for rec in records)
    return {cls: counts[cls] for cls in CLASSES} | dict(counts)
