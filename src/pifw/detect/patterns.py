"""The rule layer: regular expressions, each with a weight and a provenance.

Every rule records ``motivated_by`` — the attack families that would have caused
somebody to write it. Under a leave-one-family-out fold the rules motivated by
the held-out family are switched off, for the same reason the normalisation
stages are: a rule written *because* of a technique is not evidence that the
firewall generalises to that technique.

One measured consequence, which came out the opposite way round from the guess
that is usually made about it. ``override.verb_scope`` was written against
``direct_override``, and it is also what catches ``encoding_wrapper`` and
``homoglyph`` once normalisation has undone their disguise — those families are,
after all, the plain instruction wearing a coat. The obvious prediction is that
holding out ``direct_override`` would be catastrophic.

It is the *easiest* fold: 0.00% bypass. Every other family embeds the same core
instruction, so the learned layer sees thousands of examples of that phrasing
from eleven other families and catches the plain one without any rule at all.
The families that collapse are the two whose *disguise* nothing else in the
corpus teaches — ``encoding_wrapper`` at 100% and ``homoglyph`` at 99%. What
generalises across techniques is the payload; what does not is the wrapper.

**Regular expressions are a floor, not a defence.** Anything here can be evaded
by paraphrase, and the evaluation exists to say by how much. The rules are worth
keeping because they are cheap, auditable, and they explain themselves — a
verdict that names ``exfil.reveal_prompt`` tells an on-call engineer more than a
score of 0.83.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Every pattern is bounded. Nothing here nests a quantifier inside a
#: quantifier, and every wildcard run carries an explicit upper bound, because
#: this code runs on attacker-supplied text in front of the thing it protects
#: and a regex that backtracks exponentially is a denial-of-service primitive
#: that arrived through the front door.
MAX_GAP = 60


@dataclass(frozen=True, slots=True)
class Rule:
    """One pattern, what it means, how much it counts, and why it exists."""

    rule_id: str
    summary: str
    pattern: re.Pattern[str]
    #: Evidence weight in [0, 1]. Combined by the ensemble, not summed here:
    #: three weak rules firing on the same clause is one observation, and
    #: adding them is how a rule layer produces confident nonsense.
    weight: float
    motivated_by: frozenset[str]


def _rule(
    rule_id: str,
    summary: str,
    pattern: str,
    weight: float,
    motivated_by: set[str],
) -> Rule:
    return Rule(
        rule_id=rule_id,
        summary=summary,
        pattern=re.compile(pattern, re.IGNORECASE | re.MULTILINE),
        weight=weight,
        motivated_by=frozenset(motivated_by),
    )


RULES: tuple[Rule, ...] = (
    _rule(
        "override.verb_scope",
        "An override verb applied to the scope of earlier instructions.",
        r"\b(?:ignore|disregard|forget|set aside|override|discard|bypass|suspend)\b"
        r"(?:\s+\w+){0,3}\s+"
        r"\b(?:previous|prior|earlier|above|original|preceding|foregoing)\b",
        0.55,
        {"direct_override"},
    ),
    _rule(
        "override.instruction_noun",
        "A reference to the instructions themselves as an object to be changed.",
        r"\b(?:previous|prior|earlier|original|preceding)\s+"
        r"(?:instructions?|directives?|rules?|prompts?|configuration|policy)\b",
        0.30,
        {"direct_override"},
    ),
    _rule(
        "override.new_task",
        "An announcement that the real instruction is the one arriving now.",
        r"\b(?:your new (?:task|instruction|role) is"
        r"|the real instruction is"
        r"|for the rest of this session, you"
        r"|from now on,? you (?:must|will|are))\b",
        0.40,
        {"direct_override"},
    ),
    _rule(
        "role.you_are_now",
        "A reassignment of identity, as opposed to a request for a style.",
        r"\b(?:you are now\b|you will now act as\b|pretend (?:to be|you are)\b"
        r"|act as if you (?:are|were)\b|from now on you are\b)",
        0.35,
        {"role_assumption"},
    ),
    _rule(
        "role.unrestricted",
        "A persona defined by the absence of a constraint.",
        r"\b(?:(?:no|without|free of) (?:restrictions?|filters?|polic(?:y|ies)|guardrails?|limits?)"
        r"|unrestricted (?:mode|assistant|version|model)"
        r"|developer mode|debug console|no opinions)\b",
        0.45,
        {"role_assumption"},
    ),
    _rule(
        "delimiter.close_tag",
        "A closing marker for a block the message is not supposed to own.",
        r"(?:</(?:system|instructions?|context|prompt)>|<\|im_(?:start|end)\|>)",
        0.45,
        {"delimiter_escape"},
    ),
    _rule(
        "delimiter.forged_header",
        "A line that opens what looks like a new system turn.",
        r"^(?:\s*(?:#{1,3}|-{2,})\s*)?(?:system override|new system message|system:"
        r"|\[system\]|<system>)",
        0.40,
        {"delimiter_escape"},
    ),
    _rule(
        "delimiter.end_marker",
        "An end-of-input marker, which only the platform should be emitting.",
        r"(?:\[?\s*end of (?:document|context|input|user input)\s*\]?"
        r"|-{2,}\s*end of context\s*-{2,})",
        0.35,
        {"delimiter_escape"},
    ),
    _rule(
        "encoding.decode_and_obey",
        "An instruction to decode something and then act on what it says.",
        rf"\b(?:decode|decrypt|un-?rot13|apply rot13|read)\b.{{0,{MAX_GAP}}}?"
        r"\b(?:and|then)\s+(?:do what it says|follow|obey|comply|carry out|execute)\b",
        0.60,
        {"encoding_wrapper"},
    ),
    _rule(
        "encoding.read_backwards",
        "An instruction to read the message in reverse.",
        r"\bread (?:this|the following|it) backwards\b",
        0.50,
        {"encoding_wrapper"},
    ),
    _rule(
        "exfil.reveal_prompt",
        "A request for the instructions, context or configuration behind the assistant.",
        rf"\b(?:reveal|show|print|output|repeat|disclose|list|summari[sz]e|state)\b.{{0,{MAX_GAP}}}?"
        r"\b(?:system prompt|initial instructions|your instructions|context window"
        r"|developer message|hidden context|configuration values|credentials this session)\b",
        0.60,
        {"exfiltration"},
    ),
    _rule(
        "exfil.channel",
        "A named channel for getting the disclosed text out of the conversation.",
        r"\b(?:markdown image|image whose url contains|as a link i can click"
        r"|encoded in base64 so it renders)\b",
        0.35,
        {"exfiltration"},
    ),
    _rule(
        "exfil.repeat_above",
        "A request for the text above the message, whatever it happens to be.",
        r"\b(?:repeat everything above|print the first line of your instructions"
        r"|list every directive you were given|output the full text of your configuration)\b",
        0.50,
        {"exfiltration"},
    ),
    _rule(
        "refusal.suppression",
        "A constraint on the form of the answer that removes refusal as an option.",
        r"\b(?:do not apologi[sz]e|never say (?:that )?you (?:can'?t|cannot)"
        r"|omit (?:every|all) disclaimers?|do not add warnings|do not mention any policy"
        r"|never begin with|skip the part where you explain your limits"
        r"|leave out the safety note)\b",
        0.45,
        {"refusal_suppression"},
    ),
    _rule(
        "split.assemble",
        "An instruction to join fragments and treat the join as the instruction.",
        rf"\b(?:concatenate|join|combine)\b.{{0,{MAX_GAP}}}?"
        r"\b(?:treat the result as|as your instruction|and follow (?:it|the result))\b",
        0.55,
        {"payload_splitting"},
    ),
    _rule(
        "hypothetical.no_rules",
        "A fictional frame whose entire premise is the absence of the constraint.",
        r"\b(?:story|screenplay|fictional|hypothetical|thought experiment|novel|in character)\b"
        rf".{{0,{MAX_GAP}}}?"
        r"\b(?:no (?:rules|restrictions)|removed"
        r"|without (?:any )?(?:restrictions?|polic(?:y|ies)))",
        0.35,
        {"hypothetical"},
    ),
    _rule(
        "authority.claim",
        "An assertion of an identity that would be entitled to change the rules.",
        r"\bthis is (?:the )?(?:system administrator|the developer who deployed you"
        r"|the security team|the compliance reviewer|the on-call engineer"
        r"|the platform's trust and safety lead|the person who wrote your system prompt)\b",
        0.40,
        {"authority_claim"},
    ),
    _rule(
        "authority.authorise",
        "An explicit grant of permission to set the constraint aside.",
        r"\b(?:i authorise you to|you are authorised to (?:ignore|bypass|override)"
        r"|maintenance window is open|change request approved|this is a sanctioned test)\b",
        0.45,
        {"authority_claim"},
    ),
    _rule(
        "indirect.addressed_to_model",
        "Content in a document that addresses the assistant reading it.",
        r"\b(?:note (?:for|to) any ai (?:assistant|model)"
        r"|to the model (?:processing|reading)"
        r"|automated systems:"
        r"|if you are a language model"
        r"|assistant instructions embedded)\b",
        0.65,
        {"indirect"},
    ),
    _rule(
        "translate.then_obey",
        "A translation request whose second half is an instruction to comply.",
        rf"\btranslate the following\b.{{0,{MAX_GAP}}}?"
        r"\bthen (?:carry out|do|follow|obey)\b",
        0.55,
        {"translation_pivot"},
    ),
    _rule(
        "translate.foreign_override",
        "The override instruction in a language other than English.",
        r"(?:ignorez toutes les instructions|ignora todas las instrucciones"
        r"|ignoriere alle vorherigen|ignora tutte le istruzioni"
        r"|ignore todas as instrucoes|negeer alle voorgaande)",
        0.60,
        {"translation_pivot"},
    ),
)

RULE_IDS: tuple[str, ...] = tuple(rule.rule_id for rule in RULES)
BY_ID: dict[str, Rule] = {rule.rule_id: rule for rule in RULES}


@dataclass(frozen=True, slots=True)
class RuleHit:
    """One rule firing, with the span it fired on."""

    rule_id: str
    weight: float
    span: tuple[int, int]
    matched: str


def match_rules(text: str, *, disabled: frozenset[str] = frozenset()) -> tuple[RuleHit, ...]:
    """Every enabled rule that matches, at most once each.

    Once each on purpose. A message that says "ignore previous instructions"
    four times is not four times more likely to be an attack than one that says
    it once, and counting occurrences is how a scorer ends up ranking verbosity.
    """
    hits: list[RuleHit] = []
    for rule in RULES:
        if rule.rule_id in disabled:
            continue
        found = rule.pattern.search(text)
        if found is not None:
            hits.append(
                RuleHit(
                    rule_id=rule.rule_id,
                    weight=rule.weight,
                    span=found.span(),
                    matched=found.group(0)[:120],
                )
            )
    return tuple(hits)


def rules_for_fold(held_out: str | None) -> frozenset[str]:
    """Which rules must be switched off when *held_out* is the unseen family."""
    if held_out is None:
        return frozenset()
    return frozenset(rule.rule_id for rule in RULES if held_out in rule.motivated_by)


def coverage() -> dict[str, tuple[str, ...]]:
    """Which rules each family motivated. Used by the documentation build."""
    mapping: dict[str, list[str]] = {}
    for rule in RULES:
        for family in sorted(rule.motivated_by):
            mapping.setdefault(family, []).append(rule.rule_id)
    return {family: tuple(ids) for family, ids in sorted(mapping.items())}
