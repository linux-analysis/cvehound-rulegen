"""Identifier extraction and token-count estimation.

Identifier extraction mirrors the corpus context-tier measurement: C-like
identifiers, minus C keywords and cocci markup, so 'which tokens does this
text carry' means the same thing in extraction, prompt building, and analysis.

Token counts are an estimation concern, not a correctness one: budgets are
enforced against whichever counter is configured, and the counter is part of
the input-policy identity. The default is a deterministic dependency-free
approximation; an exact HF tokenizer can be plugged in for experiments.
"""

import re
from collections import Counter
from collections.abc import Callable

IDENT_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]{2,}')

# A big multi-line string that .split()s is the readable form for these word
# lists; ruff's "use a literal" (SIM905) does not apply.
C_KEYWORDS = frozenset(
    """
    if else return struct union enum sizeof for while do goto break continue
    switch case default static const void int char long short unsigned signed
    bool float double volatile register extern inline typedef auto
    NULL true false u8 u16 u32 u64 s8 s16 s32 s64 __user __init __exit
    likely unlikely
    """.split()  # noqa: SIM905
)

COCCI_KEYWORDS = frozenset(
    """
    when any exists forall depends on virtual detect disable using strict
    identifier expression statement type constant symbol position iterator
    declarer name local idexpression
    """.split()  # noqa: SIM905
)

STOPLIST = C_KEYWORDS | COCCI_KEYWORDS


def identifiers(text: str) -> Counter[str]:
    """C-like identifiers in the text, minus keywords."""
    counts: Counter[str] = Counter(IDENT_RE.findall(text))
    for word in STOPLIST:
        counts.pop(word, None)
    return counts


def approx_token_count(text: str) -> int:
    """Deterministic token estimate: ~3.5 bytes/token for code-heavy text."""
    return max(1, len(text.encode('utf-8', errors='replace')) * 2 // 7)


TokenCounter = Callable[[str], int]


def fit_pieces(
    pieces: list[str], cap: int, count: TokenCounter, from_end: bool = False
) -> tuple[list[str], int]:
    """The longest prefix (or suffix) of `pieces` whose concatenation counts within `cap`.

    Counting the whole concatenation, not the sum of the pieces, is what makes
    the answer exact under any counter: per-piece counts round each piece up or
    down and the sums drift by a token a line. A binary search over the cut
    keeps that at O(log n) encodes. Returns (kept, dropped); `kept` is never
    empty when `pieces` is not, so a marker can always be attached.
    """
    if not pieces:
        return [], 0
    ordered = pieces[::-1] if from_end else pieces
    lo, hi = 1, len(ordered)  # keep at least one piece
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if count(''.join(ordered[:mid])) <= cap:
            lo = mid
        else:
            hi = mid - 1
    kept = ordered[:lo]
    return (kept[::-1] if from_end else kept), len(pieces) - lo


def make_counter(tokenizer_json: str | None = None) -> tuple[str, TokenCounter]:
    """(counter identity, counter). The identity goes into the policy hash."""
    if tokenizer_json is None:
        return ('approx-3.5bpt', approx_token_count)
    from tokenizers import Tokenizer  # optional dependency

    tok = Tokenizer.from_file(tokenizer_json)
    return (f'hf:{tokenizer_json}', lambda text: len(tok.encode(text).ids))
