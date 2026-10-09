# Domain Docs

This repository uses a single-context domain model.

## Before exploring

Read root `GLOSSARY.md` and relevant decisions in `docs/adr/`.

If these files do not exist, proceed silently. Do not suggest creating
them upfront. Domain modeling creates them lazily as terms and decisions
are resolved.

## Layout

- `GLOSSARY.md`: shared domain terminology.
- `docs/adr/`: architecture decision records.

## Vocabulary

Use glossary terms consistently in issues, proposals, hypotheses, and
tests. If a needed term is missing, reconsider whether it belongs in the
domain or note the gap for domain modeling.

## Decision conflicts

Explicitly flag proposals that contradict an existing ADR and explain
why the decision should be reopened.
