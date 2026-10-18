"""Mechanical canonicalization of model output before scoring.

`patch_to_detect` turns a semantic *patch* (the way Coccinelle is usually
written: `-` vulnerable lines, `+` fixed lines) into a CVEhound *detection*
rule: removed lines become starred lines, added lines become `... when !=`
constraints with the following statement starred. It is the mechanical
baseline's logic applied to the model's own localisation, so scoring the
canonicalized output measures "can the model express the fix in SmPL" while the
strict contract measures "can it write the detection rule as such". Both are
reported; neither replaces the other.
"""

import re
from collections.abc import Callable

from rulegen import shapes, tiers

# The block structure lives with the rest of the SmPL knowledge in rulegen.tiers.
RULE_HEADER_RE = tiers.RULE_HEADER_RE
blocks = tiers.blocks


def _is_statement_line(line: str) -> bool:
    text = line.strip()
    return bool(text) and not text.startswith(
        ('...', '@', '}', '{', '(', '|', ')', '//', '/*', '*')
    )


def patch_to_detect(rule_text: str) -> str | None:
    """Convert `-`/`+` transformation lines to a detection pattern; None if hopeless."""
    lines = rule_text.split('\n')
    if not any(
        line.startswith(('-', '+')) for line in lines if not line.startswith(('---', '+++'))
    ):
        return None
    out = list(lines)
    for _header, meta_end, end in reversed(blocks(lines)):
        start = meta_end + 1
        block = lines[start:end]
        new: list[str] = []
        i = 0
        while i < len(block):
            line = block[i]
            if line.startswith('-'):
                new.append('*' + line[1:])
                i += 1
                continue
            if line.startswith('+'):
                run = []
                while i < len(block) and block[i].startswith('+'):
                    run.append(block[i][1:])
                    i += 1
                had_minus = bool(new) and new[-1].startswith('*')
                if had_minus:
                    continue  # a change: the starred old line already carries it
                added = shapes.statements(run)
                if not added:
                    continue
                new.extend(f'\t... when != {stmt}' for stmt in added[:3])
                # Star the statement the addition guarded: the next context statement.
                j = i
                while j < len(block) and not _is_statement_line(block[j]):
                    j += 1
                if j < len(block):
                    block[j] = '*' + block[j].lstrip(' ')  # keep tabs, drop the context space
                    block[j] = (
                        block[j] if block[j].startswith('*\t') else '*\t' + block[j][1:].lstrip()
                    )
                continue
            new.append(line)
            i += 1
        out[start:end] = new
    text = '\n'.join(out)
    if not re.search(r'^\*', text, re.MULTILINE):
        return None
    return text


# ---------------------------------------------------------------------------
# Polish: SmPL slips a maintainer fixes without thinking, applied mechanically.

_LABEL_RE = re.compile(r'^\s*[A-Za-z_]\w*:\s*$')
_ITERATOR_RE = re.compile(r'^\s*\*?\s*([A-Za-z_]\w*)\s*\(.*\)\s*\{\s*$')
_FIELD_USE_RE = re.compile(r'(?:->|\.)\s*([A-Za-z_]\w*)')
# Every SmPL declaration kind, longest first (tiers owns the list).
_METAVAR_DECL_RE = re.compile(
    r'^(' + '|'.join(kind.replace(' ', r'\s+') for kind in tiers.METAVAR_KINDS) + r')\s+(.+);\s*$'
)
# Kinds whose declared name is the point of the declaration: a cast needs its
# typedef, a position its name. The rewriting passes leave them alone.
_UNTOUCHED_KINDS = frozenset({'typedef', 'position'})
_STRUCT_TAG_RE = re.compile(r'\b(?:struct|union|enum)\s+([A-Za-z_]\w*)')
_POSITION_DECL_RE = re.compile(r'^position\s+[^;]*;\s*$', re.MULTILINE)


def normalize_heads(lines: list[str], start: int, end: int) -> None:
    """`name(any params...) ... {` at the top of a pattern becomes `name(...)`.

    The function name is the anchor; spelled-out parameters only add ways to
    fail (metavariables used as types, renamed parameters across versions).
    """
    i = start
    while i < end and not lines[i].strip():
        i += 1
    if i >= end:
        return
    if lines[i].startswith(('*', '-', '+', ' ', '\t')):
        return
    name = shapes.function_head(lines[i])  # the same head test the mechanical baseline uses
    if name is None:
        return
    rest = lines[i].partition('(')[2]
    if rest.strip().startswith('...'):
        return  # already normalized
    # The head may span lines up to the ')' that precedes '{'.
    depth = 1 + rest.count('(') - rest.count(')')
    j = i
    while depth > 0 and j + 1 < end:
        j += 1
        depth += lines[j].count('(') - lines[j].count(')')
    tail = lines[j][lines[j].rfind(')') + 1 :] if depth == 0 else ''
    lines[i : j + 1] = [f'{name}(...){tail}']


def declare_typedefs(lines: list[str], meta_start: int, meta_end: int, pattern: list[str]) -> None:
    """Add `typedef u32, u64;` for kernel typedefs the pattern casts to."""
    used = set(shapes.typedefs_used('\n'.join(pattern)))
    declared = set()
    for line in lines[meta_start:meta_end]:
        if line.strip().startswith('typedef '):
            declared.update(
                t.strip() for t in line.strip()[len('typedef ') :].rstrip(';').split(',')
            )
    missing = sorted(used - declared)
    if missing:
        lines.insert(meta_end, f'typedef {", ".join(missing)};')


def drop_struct_tag_metavars(
    lines: list[str], meta_start: int, meta_end: int, pattern: list[str]
) -> None:
    """A metavariable named like a struct/union/enum tag the pattern spells out
    cannot be both; the tag is literal, so the declaration loses the name."""
    tags = set(_STRUCT_TAG_RE.findall('\n'.join(pattern)))
    if not tags:
        return
    for i in range(meta_start, meta_end):
        match = _METAVAR_DECL_RE.match(lines[i].strip())
        if not match:
            continue
        kind, names = match.group(1), [n.strip() for n in match.group(2).split(',')]
        if kind in _UNTOUCHED_KINDS:
            continue
        kept = [n for n in names if n.split('=')[0].strip() not in tags]
        if kept != names:
            lines[i] = f'{kind} {", ".join(kept)};' if kept else ''


def drop_body_noise(lines: list[str], start: int, end: int) -> None:
    """Unstarred declarations and labels inside a body cannot follow `...` in SmPL and
    never carry the vulnerability; drop them. `goto`/`case` lines stay."""
    i = start
    # Skip the head and its opening brace.
    while i < end and lines[i].strip() != '{':
        i += 1
    for j in range(i + 1, end):
        line = lines[j]
        if line.startswith(('*', '-', '+')):
            continue
        text = line.strip()
        if not text or text.startswith(('...', '@', '(', '|', ')')):
            continue
        if _LABEL_RE.match(line) or shapes.is_declaration(text):
            lines[j] = ''


def field_metavars_to_identifier(
    lines: list[str], meta_start: int, meta_end: int, pattern: list[str]
) -> None:
    """A metavariable used as a struct field (`x.name`, `p->name`) must be an identifier."""
    fields = set(_FIELD_USE_RE.findall('\n'.join(pattern)))
    if not fields:
        return
    moved: list[str] = []
    for i in range(meta_start, meta_end):
        match = _METAVAR_DECL_RE.match(lines[i].strip())
        if not match or match.group(1) in ('identifier', *_UNTOUCHED_KINDS):
            continue
        kind, names = match.group(1), [n.strip() for n in match.group(2).split(',')]
        keep = [n for n in names if n.split('=')[0].strip() not in fields]
        move = [n for n in names if n.split('=')[0].strip() in fields and '=' not in n]
        if move:
            moved.extend(move)
            lines[i] = f'{kind} {", ".join(keep)};' if keep else ''
    if moved:
        lines.insert(meta_end, f'identifier {", ".join(dict.fromkeys(moved))};')


def declare_iterators(lines: list[str], meta_start: int, meta_end: int, pattern: list[str]) -> None:
    """`name(...) {` inside a body is an iterator macro; SmPL needs `iterator name X;`."""
    declared = set()
    for line in lines[meta_start:meta_end]:
        text = line.strip()
        if text.startswith('iterator name '):
            declared.update(n.strip() for n in text[len('iterator name ') :].rstrip(';').split(','))
    body = pattern
    # the head itself also matches the iterator shape when written `f(...) {`; skip it
    first = next((k for k, line in enumerate(body) if line.strip()), None)
    names = []
    for k, line in enumerate(body):
        if k == first:
            continue
        match = _ITERATOR_RE.match(line)
        if match and match.group(1) not in shapes.NOT_FUNCTIONS and match.group(1) not in declared:
            names.append(match.group(1))
    names = list(dict.fromkeys(names))
    if names:
        lines.insert(meta_end, f'iterator name {", ".join(names)};')


def polish(rule_text: str) -> str:
    """Head normalization, typedef declarations, tag clashes, position removal."""
    text = _POSITION_DECL_RE.sub('', rule_text)
    lines = text.split('\n')
    for start, meta_end, end in reversed(blocks(lines)):
        pattern = lines[meta_end + 1 : end]
        pattern = [
            tiers.POSITION_RE.sub('', line)
            if '@' in line and not RULE_HEADER_RE.match(line)
            else line
            for line in pattern
        ]
        lines[meta_end + 1 : end] = pattern
        normalize_heads(lines, meta_end + 1, end)
        # normalize_heads may have shortened the block: recompute its end.
        end = tiers.next_header(lines, meta_end + 1)
        drop_body_noise(lines, meta_end + 1, end)
        pattern = lines[meta_end + 1 : end]
        for metavar_pass in _METAVAR_PASSES:
            metavar_pass(lines, start + 1, meta_end, pattern)
    out = '\n'.join(lines)
    out = re.sub(r'\n{3,}', '\n\n', out)
    return out


# Every metavariable-block pass takes the same slice of one block.
_METAVAR_PASSES = (
    drop_struct_tag_metavars,
    field_metavars_to_identifier,
    declare_iterators,
    declare_typedefs,
)


def if_changed(new: str, old: str) -> str | None:
    """A transform's result, or None when it had nothing to change."""
    return new if new != old else None


def canonicalize(rule_text: str) -> str | None:
    """patch_to_detect (when the rule is a transformation) followed by polish."""
    converted = patch_to_detect(rule_text)
    return if_changed(polish(converted if converted is not None else rule_text), rule_text)


# The named rewritings a run or a rescore may apply to a parsed rule body before
# scoring. Each returns None when it has nothing to change.
TRANSFORMS: dict[str, Callable[[str], str | None]] = {
    'canon': canonicalize,  # patch-to-detect + polish
    'patch-to-detect': patch_to_detect,
    'polish': lambda text: if_changed(polish(text), text),
}


def transform_fn(name: str | None) -> Callable[[str], str | None] | None:
    """The transform a config names, or None for 'no transform'."""
    if name in (None, '', 'none'):
        return None
    if name not in TRANSFORMS:
        raise ValueError(f'unknown transform {name!r}; known: {sorted(TRANSFORMS)}')
    return TRANSFORMS[name]
