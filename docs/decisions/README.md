# Decisions

One file per significant architectural or product decision. Each entry captures:

- The decision (one line, in imperative or declarative form)
- Context — what problem the decision addresses
- Alternatives considered, with reasons each was not selected
- Consequences — what the decision implies for adjacent systems
- References — prior art, papers, RFCs, related discussions

Format suggestion (lightweight ADR):

```
# DNNNN — Short title

**Status:** Proposed | Accepted | Superseded by [DNNNN]
**Date:** YYYY-MM-DD

## Context
What problem this decision addresses.

## Decision
What was chosen.

## Alternatives
What else was considered, and why each was not selected.

## Consequences
What this implies. Both intended consequences and accepted tradeoffs.

## References
Links to prior work, papers, related decisions.
```

When an open question from `../open-questions.md` is resolved, the resolution moves here as a decision file, and the question entry gets a closing note linking to the decision file.
