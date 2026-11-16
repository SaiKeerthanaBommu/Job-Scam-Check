# Scam checker for students and new grads

Paste a job, recruiter, or interview-invitation message and get a **risk estimate** with the exact lines that triggered it.
Runs locally. Standard library only (scikit-learn is optional). Nothing is stored or uploaded.

## Run it
```bash
python -m checker message.txt --sender recruiter@gmail.com   # command line
python -m checker --serve                                    # web page at http://127.0.0.1:8765
python -m checker message.txt --sender a@b.com --lookup      # also checks domain age (sends only the domain name)
```

## What it checks
- **Text rules**: upfront fees, check/transfer requests, chat-app interviews, personal data before an interview, registration/form before interview, reshipping or data-entry jobs, generic greeting, vague employer, too-good pay, urgency, mass mailing.
- **Verification signals**: free-email recruiter, sender domain vs. the company named (including look-alikes like `amaz0n`), link shorteners, form links, raw-IP links, odd TLDs, optional domain age.
- **Citation check**: every finding must point at a real line and quote text that is really there, or it is dropped.
- **Optional classifier** (TF-IDF + logistic regression) trained only on your labeled train split.

## Limits (read this)
- It gives a **risk estimate, not a verdict**. Real employers sometimes trip checks (e.g. a bulk "Dear Candidate" email, or a form link from a real firm).
- A "low" result does not mean safe. Verify the company on its official site.
- The built-in tests use small invented examples. **They are not a benchmark.** Accuracy numbers only count when you run `eval` on your own real, verified labels (see `LABELING.md`).
- Domain-age lookup uses the public RDAP service and can fail; failure is never treated as a warning sign.

## Evaluate on your own data
```bash
python scripts/check_data.py     # schema + PII check
python scripts/make_split.py     # once, after labeling (70/30, seeded)
python -m eval.run_eval          # test split only: scam recall, false-alarm rate, citation validity
```

## Privacy
Raw messages stay in `data/raw/` (git-ignored). Redact names, emails, phones, and links before adding rows to `data/labeled.csv`; CI fails if PII is found. Do not scrape Reddit or job sites.

## Tests
```bash
pip install -r requirements-dev.txt && python -m pytest -q
```
