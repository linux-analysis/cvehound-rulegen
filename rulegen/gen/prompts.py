"""The system prompt registry and chat-message assembly.

build_prompt() owns the user turn and its hash; this module adds the system
turn and hashes the whole message list, so a run log can prove exactly what
the model saw. The registry is keyed so `system_prompt_id` and its sha stay in
every manifest; editing the text in place would silently change every future
run — bump the key instead.
"""

import hashlib
import json
from dataclasses import dataclass, field

from rulegen import promptbuild
from rulegen.schema import ExampleRecord
from rulegen.tokens import TokenCounter, approx_token_count

# sys-v1: the cvehound rule contract stated natively -- no `virtual`
# declaration and no header `exists` (T0 rejects both) -- and the acceptance
# criterion spelled out as the oracle applies it: fire on the vulnerable code,
# silent on the fixed code, on kernels carrying the fix and on unrelated code at
# the same paths.
SYSTEM_PROMPT_V1 = """\
You write Coccinelle detection rules for CVEhound, which checks Linux kernel \
sources for known CVEs. Given a kernel fix commit, write a rule that matches \
the VULNERABLE code (before the fix) and does not match fixed code.

A CVEhound rule is a DETECTION rule, not a patch: it never contains `+` or `-` \
lines. It reports by marking the identifying vulnerable line(s) with `*` in the \
first column. A rule with no `*` line reports nothing and is rejected.

Decide what to match from the fix diff:
- fix ADDS code (a check, an init): match its absence with `... when != <the added statement>`
  placed before the line that needed it, and star that line
- fix CHANGES a value, flag or condition: star the old line
- fix REMOVES code: star the removed line
- fix REFACTORS logic: star the distinctive vulnerable statement

Rules of construction:
- Anchor the pattern inside the function the fix touched: `funcname(...) { ... }`.
  A literal function name needs no declaration.
- Declare metavariables for names that vary (`identifier x;`, `expression E;`,
  `type T;`). Spell out only rare, identifying names (the called function, the
  field, the macro); local variable names belong in metavariables.
- Declare kernel typedefs you spell out in casts: `typedef u32, u64;` in the
  metavariable block.
- Use `...` between statements and `... when any` around statement context.
  Never use `<... ...>`, `<+... ...+>`, `+`/`-` lines, `@script:python@`,
  `position` metavariables or `@p` annotations.
- Declare no `virtual` rules, and put no `exists` in a rule header: a starred
  rule already matches on some path. When a guard must hold on every path,
  write `... when forall` on that ellipsis.
- Independent vulnerable sites = separate starred rules (OR). Conditions that
  must all hold = rules chained with `depends on`, only the last one starred;
  helper rules that recognize the fix never star.
- Match the invariant that held for the whole vulnerable range, not one era's
  spelling; use `\\(old\\|new\\)` for renamed identifiers.
- Keep starred rules at five or fewer and keep the pattern short (the
  identifying lines, not the whole function).
- The rule must fire on the vulnerable code and stay silent on the fixed code,
  on maintained kernels that carry the fix, and on unrelated code at the same
  paths. When the fix's spelling changed across versions, match the invariant
  rather than one era's spelling.

Skeleton (the fix added `if (!p) return -ENOMEM;` after an allocation):
```
/// Files: drivers/foo/bar.c

@r@
expression p, E;
@@

bar_probe(...)
{
\t... when any
\tp = kmalloc(E, GFP_KERNEL);
\t... when != if (!p) return -ENOMEM;
*\tbar_setup(p);
\t... when any
}
```

Output exactly one fenced code block containing the rule file:
line 1: `/// Files: <space-separated kernel-relative paths the rule matches in>`,
then the rule(s). Do not emit Fix:/Fixes:/Version: header lines — they are added
mechanically. No prose inside the block.
"""

SYSTEM_PROMPTS: dict[str, str] = {
    'sys-v1': SYSTEM_PROMPT_V1,
}

DEFAULT_SYSTEM_PROMPT = 'sys-v1'


def system_sha(name: str) -> str:
    return hashlib.sha256(SYSTEM_PROMPTS[name].encode()).hexdigest()


@dataclass
class BuiltPrompt:
    messages: list[dict[str, str]]
    prompt_sha: str  # build_prompt's hash of the user turn (policy/budget/counter aware)
    messages_sha: str  # hash of the full message list as sent
    token_estimate: int
    truncated: list[str]
    sections: dict[str, int] = field(default_factory=dict)  # token count per section


def messages_sha(messages: list[dict[str, str]]) -> str:
    canonical = json.dumps(messages, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    return hashlib.sha256(canonical.encode()).hexdigest()


def build_messages(
    example: ExampleRecord,
    policy: str,
    budget_tokens: int,
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
    hide_cve_id: bool = True,
    count: TokenCounter = approx_token_count,
    counter_id: str = 'approx-3.5bpt',
) -> BuiltPrompt:
    # The budget is for the whole request: the system turn is spent first,
    # the user turn is built inside what is left.
    system = SYSTEM_PROMPTS[system_prompt]
    system_tokens = count(system)
    prompt = promptbuild.build_prompt(
        example,
        policy,
        budget_tokens=max(promptbuild.DIFF_FLOOR + 1, budget_tokens - system_tokens),
        count=count,
        counter_id=counter_id,
        hide_cve_id=hide_cve_id,
    )
    messages = [
        {'role': 'system', 'content': system},
        {'role': 'user', 'content': prompt.text},
    ]
    return BuiltPrompt(
        messages=messages,
        prompt_sha=prompt.sha256,
        messages_sha=messages_sha(messages),
        token_estimate=prompt.token_estimate + system_tokens,
        truncated=prompt.truncated,
        sections={'system': system_tokens, **prompt.sections},
    )
