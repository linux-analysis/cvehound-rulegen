"""Structured oracle feedback for the repair loop, and the self-critique control.

render_feedback() turns a Score into short, tier-ordered text a model can act
on: what failed, where, and the construction rule it violates. It names only
what the model may legitimately see — never the gold rule or its paths.
CRITIQUE_PROMPT is the c' control: the same repair turn with no oracle
information at all, so the pair isolates what execution feedback is worth.
"""

from rulegen.schema import (
    ERROR,
    FIRE,
    HARD_VERDICTS,
    LEG_BP,
    LEG_BP_PRE,
    LEG_DECOY,
    LEG_RANGE,
    LEG_TREE,
    NO_FILES,
    SILENT,
    TIMEOUT,
    TRUNCATED,
    UNSUPPORTED,
    ExampleRecord,
    Score,
    branch_of_ref,
)

CONTRACT_REMINDER = (
    'Output exactly one fenced code block with the corrected rule file: line 1 '
    '`/// Files: <kernel-relative paths>`, then the rule(s). Declare no `virtual` rules, '
    'put no `exists` in a rule header, and do not emit Fix:/Fixes:/Version: lines (they are '
    'added mechanically); no prose inside the block.'
)

CRITIQUE_PROMPT = (
    'Review the rule you just wrote against this checklist, then output a corrected rule:\n'
    '- Is the pattern anchored inside the function the fix touched?\n'
    '- Does `*` sit only on the line(s) that identify the vulnerability, in the one rule that reports?\n'
    '- If the fix ADDED a check or initialization, does the rule match its absence with '
    '`... when != <the added code>`? If the fix CHANGED or REMOVED code, does the rule match the '
    'old code and not the new?\n'
    '- Do the `Files:` paths name the files the vulnerable code lives in?\n'
    '- Would the pattern match the code as it was spelled across the whole vulnerable range, and '
    'stay silent on the fixed code? Use `\\(old\\|new\\)` for renamed identifiers.\n'
    '- Is there at least one rare literal token (a function or macro name) so the prefilter stays '
    'selective, and no `<+... ...+>`?\n'
    f'{CONTRACT_REMINDER}'
)

MAX_STDERR_LINES = 12


def _all_names(example: ExampleRecord) -> str:
    """Every path the candidate files have had: current names plus their in-range renames."""
    names = list(example.files_candidates)
    for _path, older in sorted(example.historical_names.items()):
        names.extend(n for n in older if n not in names)
    return ', '.join(names)


def _tail(text: str, lines: int = MAX_STDERR_LINES) -> str:
    parts = [line for line in text.strip().splitlines() if line.strip()]
    return '\n'.join(parts[-lines:])


def render_feedback(score: Score, example: ExampleRecord) -> str:
    """What the oracle found wrong with the rule, as instructions for the next attempt."""
    fix, fixes = example.fix, example.fixes
    out: list[str] = ['The rule you wrote was checked against the kernel history. Results:']

    if score.fail_class == 'contract':
        out.append(
            '- Your reply contained no fenced code block starting with `/// Files:`. '
            'The rule must be a single fenced block in the required format.'
        )
    elif score.fail_class == 'structure':
        out.append('- The rule file is malformed:')
        out.extend(f'  - {failure}' for failure in score.t0_failures)
    elif score.fail_class == 'parse':
        out.append('- spatch could not parse the rule (`spatch --parse-cocci`):')
        out.append('```')
        out.append(_tail(score.t1_stderr) or 'parse error')
        out.append('```')
        out.append(
            '  Common causes: a C construct SmPL cannot express (labels, `#if`, casts to undeclared '
            'typedefs — declare them with `typedef name;` in the metavariable block), an unbalanced '
            '`...`, or a starred line that is not a complete statement.'
        )
    elif score.fail_class == TRUNCATED:
        out.append(
            '- The checker could not finish scanning the kernel for this rule: a fault on our '
            'side, not in the rule. Submit the rule again, unchanged or cheaper.'
        )
    elif score.fail_class in HARD_VERDICTS:
        what = {
            ERROR: 'spatch failed while running the rule',
            TIMEOUT: 'spatch exceeded its time budget while running the rule',
            UNSUPPORTED: 'the rule needs a newer spatch than the one deployed',
        }[score.fail_class]
        out.append(
            f'- {what}. Keep the pattern anchored in a named function, use `... when any` instead '
            'of `<+... ...+>`, and keep a rare literal token so few files are scanned.'
        )
    elif score.fail_class == 'harness':
        out.append('- The checker crashed on this rule; simplify the pattern and try again.')

    if score.t1_grep_query is False:
        out.append(
            '- spatch inferred no grep query for the rule: every file in the tree would be parsed. '
            'Add a literal function, macro or field name to the pattern.'
        )

    # A check that did not finish has no answer to describe: the per-leg lists
    # below read only answered legs, and the unfinished ones are counted once.
    unfinished = [leg for leg in score.legs if leg.gating and leg.verdict in HARD_VERDICTS]
    if unfinished and score.fail_class not in HARD_VERDICTS:
        kinds = {
            verdict: sum(1 for leg in unfinished if leg.verdict == verdict)
            for verdict in HARD_VERDICTS
        }
        counted = ', '.join(f'{verdict} {n}' for verdict, n in kinds.items() if n)
        advice = []
        if kinds[TIMEOUT]:
            advice.append(
                'a timeout means the rule is too expensive: keep a rare literal token so few '
                'files are scanned'
            )
        if kinds[TRUNCATED] or kinds[ERROR]:
            advice.append('an error or a truncated scan is a fault on our side, not in the rule')
        out.append(
            f'- {len(unfinished)} check(s) did not complete ({counted})'
            + (': ' + '; '.join(advice) if advice else '')
            + '.'
        )

    legs = {leg.name: leg for leg in score.legs}
    leg = legs.get('fix~')
    if leg is not None and not leg.ok:
        if leg.verdict == NO_FILES:
            out.append(
                f'- None of your `Files:` paths exist in the vulnerable tree (commit `{fix}~`). '
                'Choose from these candidate paths: ' + ', '.join(example.files_candidates)
            )
        elif leg.verdict == SILENT:
            out.append(
                f'- The rule did NOT fire on the vulnerable code (commit `{fix}~`). The pattern is '
                'too specific, anchored in the wrong function, or spells the code differently from '
                'the fix diff. Match the removed/old lines from the diff as they appear there.'
            )
        else:
            out.append(f'- Checking the vulnerable code (commit `{fix}~`) ended in: {leg.verdict}.')
    leg = legs.get('fix')
    if leg is not None and not leg.ok and leg.verdict == FIRE:
        out.append(
            f'- The rule ALSO fires on the fixed code (commit `{fix}`): it does not distinguish '
            'vulnerable from fixed. If the fix added a check, require its absence with '
            '`... when != <the added code>`; if the fix changed or removed code, match the old '
            'code exactly so the new code no longer matches.'
        )
    leg = legs.get('fixes')
    if leg is not None and not leg.ok and fixes:
        if leg.verdict == NO_FILES:
            out.append(
                f'- Your `Files:` paths (with the earlier names of those files, added '
                f'automatically) did not exist when the bug was introduced (commit `{fixes}`): '
                f'the vulnerable code lived elsewhere then. Choose from the candidate paths and '
                f'their earlier names: {_all_names(example)}'
            )
        elif leg.verdict == SILENT:
            out.append(
                f'- The rule did NOT fire at the commit that introduced the bug (`{fixes}`): the '
                'code was spelled differently then. Match the invariant of the vulnerability, not '
                "one era's spelling; use `\\(old\\|new\\)` for identifiers that were renamed."
            )
    leg = legs.get('fixes~')
    if leg is not None and not leg.ok and leg.verdict == FIRE and fixes:
        out.append(
            f'- The rule fires BEFORE the bug was introduced (commit `{fixes}~`), on code that was '
            'not vulnerable: the pattern is too generic.'
        )
    unseen = [leg.ref for leg in score.legs_of(LEG_BP_PRE) if leg.verdict == NO_FILES]
    if unseen:
        out.append(
            f'- None of your `Files:` paths (with their earlier names, added automatically) exist '
            f'on {len(unseen)} stable branch(es) that carried the bug '
            f'({", ".join(branch_of_ref(ref) for ref in unseen)}): the vulnerable code lives in '
            f'another file there. Choose from: {_all_names(example)}'
        )
    missed = [leg.ref for leg in score.legs_of(LEG_BP_PRE) if leg.verdict == SILENT]
    if missed:
        names = ', '.join(
            f'{branch_of_ref(ref)} (before commit `{ref.partition("@")[2][:12]}`)' for ref in missed
        )
        out.append(
            f'- The rule did NOT fire on the vulnerable code of {len(missed)} stable branch(es) '
            f'just before the fix was backported there ({names}): the backport spells the code '
            'differently from mainline. Match the invariant of the vulnerability, not one '
            "era's spelling; use `\\(old\\|new\\)` for renamed identifiers."
        )
    still = [leg.ref for leg in score.legs_of(LEG_BP) if leg.verdict == FIRE]
    if still:
        names = ', '.join(
            f'{branch_of_ref(ref)} (commit `{ref.partition("@")[2][:12]}`)' for ref in still
        )
        out.append(
            f'- The rule still fires on {len(still)} stable branch(es) after the fix landed there '
            f"({names}): it is over-broad or matches one era's spelling of the fix. Tighten the "
            'pattern to the vulnerable shape.'
        )
    decoys = [leg.ref for leg in score.legs_of(LEG_DECOY) if leg.verdict == FIRE]
    if decoys:
        out.append(
            f'- The rule matches unrelated kernel code placed at your `Files:` path '
            f'({len(decoys)} of the decoy files): the pattern is generic. Add the identifying '
            'literal names (function, field, macro) of the vulnerable code.'
        )
    if score.t0_anchored is False:
        out.append(
            '- The rule names nothing of the vulnerable code: every identifier is a metavariable '
            'or common kernel vocabulary, so the pattern would describe any function. Spell out '
            'the identifying names (the function it is anchored in, the called function, the '
            'field, the macro).'
        )
    if score.t0_wildcards:
        names = ', '.join(f'`{name}`' for name in score.t0_wildcards)
        out.append(
            f'- {names} stands where a function name belongs on a report line (a starred call, '
            'or the function that anchors the rule): spell out the real name. Metavariables '
            'belong to arguments, local variables and renamed fields.'
        )
    if score.t4_unrelated_files:
        out.append(
            f"- {score.t4_unrelated_files} unrelated files under lib/ pass the rule's grep "
            'prefilter: add a rarer literal token so the rule stays cheap.'
        )
    ranges = [
        leg.ref
        for leg in score.legs_of(LEG_RANGE)
        if not leg.ok and leg.verdict in (SILENT, NO_FILES)
    ]
    if ranges:
        # Refs are tags in tags mode and full shas in commits mode; either way
        # twelve characters name them.
        shown = ', '.join(ref[:12] for ref in ranges[:6])
        out.append(
            f'- The rule misses the vulnerable code at {len(ranges)} kernel state(s) inside the '
            f'vulnerable range (commits or tags {shown}): match the invariant across versions.'
        )
    trees = [branch_of_ref(leg.ref) for leg in score.legs_of(LEG_TREE) if leg.verdict == FIRE]
    if trees:
        out.append(
            f'- A whole-tree scan at the backport commit fires on {len(trees)} stable branch(es) '
            f'({", ".join(trees)}): the pattern matches code outside the vulnerable site.'
        )

    if len(out) == 1:
        out.append(
            '- No check failed, yet the rule is not accepted; make the pattern more specific.'
        )
    out.append('')
    out.append('Write a corrected rule. ' + CONTRACT_REMINDER)
    return '\n'.join(out)


NORMALIZED_NOTE = (
    'Your reply was rewritten into detection form before it was checked (the `-`/`+` '
    'lines became starred lines and `... when !=` constraints): the rule shown as your '
    'reply above is that form, the one the results below describe and what your next '
    'answer should improve on.\n'
)


def feedback_turn(kind: str, score: Score, example: ExampleRecord, normalized: bool = False) -> str:
    """The repair turn: a note when the reply was rewritten, then why it failed.

    `normalized` says the reply shown was the run's own mechanical rewriting of
    the model's rule -- not oracle information, so both arms see the note and
    the critique control still learns nothing about the kernel from it.
    """
    body = render_feedback(score, example) if kind == 'oracle' else CRITIQUE_PROMPT
    return NORMALIZED_NOTE + body if normalized else body
