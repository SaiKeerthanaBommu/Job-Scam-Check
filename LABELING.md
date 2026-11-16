# Labeling guide

Goal: about 60 examples, so the checker can be measured instead of guessed at.

## Labels (use exactly these)
- `scam`: you are confident it is fraudulent (asks you to pay, cash a check, or move to a chat app
  for a "job"; impersonates a real company; or an official source has documented the scam).
- `legit`: you verified the company and the sender through an independent route.
- `unclear`: you could not tell. This is a valid and useful label. Do not force a guess.

## How you decided (`how_verified`)
Write one honest line: "company site lists this role", "domain registered 9 days ago",
"FTC alert describes this exact scheme", "could not verify". Leave blank only if `unclear`.

## Redaction checklist (BEFORE committing anything)
Replace with placeholders: names -> [NAME], companies you cannot name publicly -> [COMPANY],
emails -> [EMAIL], phone numbers -> [PHONE], links -> [LINK], street addresses -> [ADDRESS].
Run `python scripts/check_data.py` and fix everything it reports.

## Sources (`source`)
`own inbox`, `public report: <name>`, `reddit (hand-copied, usernames removed)`, `university alert`.
Do not scrape sites. Copy by hand and keep the example short.

## Aim for balance
About 25 scam, 25 legit, 10 unclear. Include legit recruiter outreach on purpose: it is
what the checker is most likely to wrongly flag, and that is the number worth measuring.

## Train/test split
Decide it ONCE, after labeling, with `python scripts/make_split.py`. Do not tune the rules
on the test rows. Report results from the test rows only.
