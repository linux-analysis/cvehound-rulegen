"""The mechanical baseline: star what the fix removed, `when !=` what it added.

No model. For every function the fix touches (read off the -W diff), one
starred rule: removed/changed statements are starred in order; for a pure
addition the added statement becomes `... when != <it>` and the statement
that followed the insertion is starred. No metavariables — every name is
literal. Every model row must clear this floor; its degenerate% calibrates
the audit.
"""

from typing import Any

from rulegen import shapes
from rulegen.gen.adapters.base import Completion, GenRequest
from rulegen.schema import ExampleRecord
from rulegen.tokens import approx_token_count

MECHANICAL_VERSION = 1
MAX_RULES = 5
MAX_WHEN = 3
MAX_STARS = 4


Site = tuple[str, str, list[list[str]], list[list[str]], list[list[str]]]


def _sites(example: ExampleRecord) -> list[Site]:
    """Per (file, function): removed runs, added runs, and the old-side lines after each run."""
    out: dict[tuple[str, str], tuple[list[list[str]], list[list[str]], list[list[str]]]] = {}
    order: list[tuple[str, str]] = []
    for hunk in shapes.parse_hunks(example.diff_c):
        if not hunk.file.endswith(('.c', '.h')):
            continue  # assembly has no statements to star
        old_names = shapes.enclosing_functions(hunk, 'old')
        new_names = shapes.enclosing_functions(hunk, 'new')
        i = 0
        while i < len(hunk.lines):
            if hunk.lines[i][0] == ' ':
                i += 1
                continue
            start = i
            while i < len(hunk.lines) and hunk.lines[i][0] != ' ':
                i += 1
            run = hunk.lines[start:i]
            minus = [line[1:] for line in run if line[0] == '-']
            plus = [line[1:] for line in run if line[0] == '+']
            name = next((old_names[j] for j in range(start, i) if old_names[j]), None) or next(
                (new_names[j] for j in range(start, i) if new_names[j]), None
            )
            if not name:
                continue
            key = (hunk.file, name)
            if key not in out:
                out[key] = ([], [], [])
                order.append(key)
            removed, added, tails = out[key]
            removed.append(minus)
            added.append(plus)
            # Old-side lines following this run inside the same function: where
            # the statement guarded by an added check is found.
            tails.append(
                [
                    hunk.lines[j][1:]
                    for j in range(i, len(hunk.lines))
                    if hunk.lines[j][0] in ' -' and old_names[j] == name
                ]
            )
    return [(file, name, *out[(file, name)]) for file, name in order]


def _rule(name: str, index: int, stars: list[str], whens: list[str]) -> str:
    # Casts to kernel typedefs only parse when the rule declares the names.
    typedefs = shapes.typedefs_used(' '.join(stars + whens))
    lines = [f'@r{index}@']
    if typedefs:
        lines.append(f'typedef {", ".join(typedefs)};')
    lines += ['@@', '', f'{name}(...)', '{', '\t... when any']
    lines += [f'\t    when != {w}' for w in whens]
    for pos, stmt in enumerate(stars):
        if pos:
            lines.append('\t...')
        lines.append(f'*\t{stmt}')
    lines += ['\t... when any', '}', '']
    return '\n'.join(lines)


def mechanical_rule(example: ExampleRecord) -> str | None:
    """The contract body ('/// Files:' + rules) or None when nothing is starrable."""
    rules: list[str] = []
    files: list[str] = []
    for file, name, removed_runs, added_runs, tails in _sites(example):
        stars: list[str] = []
        whens: list[str] = []
        for minus, plus, tail in zip(removed_runs, added_runs, tails, strict=True):
            removed = shapes.starrable(shapes.statements(minus))
            if not removed and minus:
                removed = shapes.complete_statement(minus, tail)
            if removed:
                stars.extend(removed)
                continue
            added = shapes.statements(plus) or shapes.complete_statement(plus, tail)
            if not added:
                continue
            whens.extend(added[:MAX_WHEN])
            guarded = shapes.starrable(shapes.statements(tail))
            if guarded:
                stars.append(guarded[0])
        stars = list(dict.fromkeys(stars))[:MAX_STARS]
        whens = list(dict.fromkeys(whens))[:MAX_WHEN]
        if not stars:
            continue
        if file not in files:
            files.append(file)
        rules.append(_rule(name, len(rules) + 1, stars, whens))
        if len(rules) >= MAX_RULES:
            break
    if not rules:
        return None
    return f'/// Files: {" ".join(files)}\n\n' + '\n'.join(rules)


class MechanicalAdapter:
    id = f'mechanical-v{MECHANICAL_VERSION}'

    def complete(self, req: GenRequest) -> Completion:
        if req.example is None:
            return Completion(error='mechanical adapter needs the example')
        rule = mechanical_rule(req.example)
        if rule is None:
            return Completion(text='', finish_reason='none', tokens_completion=0)
        text = f'```\n{rule}```\n'
        return Completion(
            text=text, finish_reason='stop', tokens_completion=approx_token_count(text)
        )

    def describe(self) -> dict[str, Any]:
        return {
            'adapter': 'mechanical',
            'version': MECHANICAL_VERSION,
            'max_rules': MAX_RULES,
            'max_when': MAX_WHEN,
            'max_stars': MAX_STARS,
        }
