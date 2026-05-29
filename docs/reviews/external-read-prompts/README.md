# External-read prompts: deployment guide

Four deep-review prompts designed for agentic execution by independent Claude instances pointed at this project directory. Each prompt instantiates a specific persona — three expert-tier and one target-user-tier — and produces a structured findings document.

## Why four independent runs, not one

The four personas are deliberately non-overlapping:

- **01-cryptographer:** evaluates construction soundness. Audit-target surfaces, composition gaps, attack sketches. No deployment or sustainability framing.
- **02-civil-society-partner:** evaluates deployment realism from a mediating-organization perspective. Audience match, partnership feasibility, externalized costs. No construction-level evaluation.
- **03-sustainability-skeptic-maintainer:** evaluates operational realism. Cadence-vs-commitment fit, deferral debt, year-three trajectory. No construction or deployment framing.
- **04-prospective-end-user:** evaluates UX and adoption friction from the actual target user's perspective. Onboarding survivability, daily-use friction tax, recovery fear, abandonment triggers. No expert framework — evaluated against the user's prior Signal/WhatsApp/Telegram usage and personal friction tolerance.

The first three are expert-tier; the fourth represents the target user, who is the one the brief is ultimately for and the one most often missing from design review. Running them as one prompt would force a single persona to context-switch across four domains, dilute findings, and produce a "balanced" output that hides hard critique. Running them independently lets each persona produce maximally-confident findings in their domain.

**Note on persona 04 specifically:** end users don't normally read design briefs. The persona is constructed so that reading the brief is _in-character_ — a prospective pilot participant invited to evaluate the brief by their digital-safety trainer, matching the actual D0013 recruitment scenario. This is what lets the agent maintain authentic non-expert friction tolerance while still being capable of reading the corpus.

## Deployment

Each prompt is a complete, standalone instruction set. Open a fresh Claude conversation (Sonnet 4.5 or Opus 4.x recommended), paste the prompt as the first user message, ensure file-system tools (Read, Grep, Glob, Bash) are enabled, and confirm the working directory is `/home/wlcarden/Desktop/Secure Messaging`.

**Important:** do not run all four in the same conversation. Each must be a fresh persona with no prior context from the others. Cross-pollination between personas defeats the independence.

**Recommended order:** any order. The personas don't depend on each other's output.

**Time budget:** allow 30-90 minutes of agent time per prompt. The reading load is substantial (~15-25 files, plus targeted grep work). Rushing the agent produces shallow findings.

## What each prompt is engineered to do

Each prompt:

1. **Specifies a concrete persona with operational reference experience.** Not "act as a cryptographer" but "a practicing cryptographer with X years of shipped-code experience who has read Y and built Z." This conditioning is what produces non-generic output.

2. **Specifies a reading plan in explicit order.** Building a model of the construction before attacking it. This prevents the failure mode where the agent finds surface-level critiques without understanding what it's critiquing.

3. **Specifies adversarial targets, not just evaluation targets.** Every section asks the agent to actively try to break something, not just summarize it. This is the difference between a review that reads like a book report and a review that finds defects.

4. **Specifies calibration anchors.** Comparable projects (Signal, Briar, Cwtch, Session, Wire, Wickr, Tor) the agent must compare Cairn against. This grounds findings in precedent rather than abstract principle.

5. **Specifies an output format with confidence calibration.** HIGH / MEDIUM / LOW confidence buckets force the agent to mark uncertainty rather than smoothing it out.

6. **Specifies anti-patterns to avoid.** Explicit bans on sycophancy ("looks good", "well-designed", "thoughtful") and vague critique ("consider X"). Required citation format (`file:line`, §-references, D-doc references).

7. **Specifies "what works well" as the last section, not the first.** And requires each item to articulate the specific failure mode it prevents. This blocks the default-helpful-assistant pattern that leads with praise.

## After the reviews land

Four artifacts will exist:

- `01-cryptographer-findings.md`
- `02-civil-society-partner-findings.md`
- `03-sustainability-skeptic-maintainer-findings.md`
- `04-prospective-end-user-findings.md`

**Next steps when all four are in:**

1. **Triage** — read all three, mark each finding as: confirmed / disputed / needs-investigation. Per the existing review pattern in this project.
2. **Consolidate** — produce a single `external-reads-consolidated.md` matching the structure of `sections-8-9-review.md` and `architecture-simplification-review.md`. Group findings by section of the brief they affect.
3. **Apply** — same iterative pattern previously used. Discuss each consolidated finding, decide accept/modify/reject, then propagate the chosen findings through the brief, decision documents, open questions, and changelog.
4. **Archive** — preserve the raw per-persona findings under `docs/reviews/external-read-prompts/` so the original confidence calibration isn't lost to consolidation.
5. **Re-run gate decision** — based on what surfaced, decide whether the brief is ready for human-expert outreach or needs another pre-outreach revision pass.

## What these prompts deliberately don't do

- **They don't substitute for human expert reads.** Claude does not have professional reputation on the line. Use these as a forcing function to surface issues before paying for or asking for human time, not as final validation.

- **They don't engage with the project's emotional or social context.** No "this is exciting work" or "the maintainer should be proud." The prompts are engineered to suppress that mode, because it pollutes the critique.

- **They don't produce uniform findings.** The cryptographer will find construction issues; the partner persona will find deployment issues; the maintainer persona will find sustainability issues; the end-user persona will find adoption-friction issues. By design, they will not converge on a single ranked finding list — that's what consolidation is for.

- **They don't have equal weight in consolidation.** A finding from persona 04 ("I would uninstall when X happens") carries different weight than a finding from persona 01 ("this construction has a chosen-prior-hash attack surface"). Both are valid; both require different responses. Triage should preserve the persona attribution when consolidating, not flatten it.

## Iterating on the prompts themselves

If the first runs produce shallow or generic output, the prompt is wrong, not the model. Common failure modes:

- **Persona drift toward generic-helpful-assistant:** strengthen the persona section. Add more concrete reference experience. Add more explicit anti-flattery instructions.
- **Findings without citations:** strengthen the anti-pattern section. Move the citation requirement earlier in the prompt.
- **Findings that summarize the brief instead of critiquing it:** strengthen the adversarial agenda. Add more "try to break X" instructions and fewer "evaluate X" ones.
- **Missing key concerns:** add them to the targeted evaluations section explicitly, rather than hoping the persona infers them.

Treat the prompts as version-controlled artifacts. Improvements propagate to future re-runs after the brief evolves.
