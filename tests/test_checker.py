import json
import threading
import urllib.request
from datetime import datetime, timezone

from checker import analyze
from checker.scoring import score
from checker.core import Finding
from eval.run_eval import evaluate

FORM = ("Dear Candidate,\nGreetings from Placemein.\nYour resume has been shortlisted with our client company.\n"
        "Kindly fill out the Google Form below. We will schedule the interview.\nhttps://forms.gle/abc123")
REG = "Submit Your Resume {You Must Complete and fill all your details in Registration then only you will get Interview Call}"
RECRUITER = ("Hi Keerthana,\nMy name is Jessica, a Technical Recruiter with Aivra Health. Your background aligns with our "
             "Software Engineer opportunity.\nPlease send your resume and your availability over the next few days.")
AMAZON = ("Hi,\nI'm a recruiter at Amazon. We're hiring for a Software Development Engineer I role.\n"
          "Would you be interested in interviewing?")
FEE = "Congratulations, you are hired! Send a $200 processing fee for your laptop before you start. Reply on WhatsApp."
CHECK = "We will mail you a check to deposit; then send the remaining money to our vendor for equipment."


def levels(text, sender=""):
    return analyze(text, sender=sender).result["level"]


def test_scams_flagged():
    assert levels(FORM) in ("medium", "high")
    assert levels(REG) in ("medium", "high")
    assert levels(FEE) == "high"
    assert levels(CHECK) == "high"


def test_legit_not_high():
    assert levels(RECRUITER) == "low"
    assert levels(AMAZON, "recruiter@amazon.jobs") == "low"


def test_free_email_plus_big_company_is_flagged():
    r = analyze("I am a recruiter at Amazon. Please reply with your resume.", sender="amazon.hr@gmail.com")
    assert r.result["level"] == "high"


def test_lookalike_domain_high():
    r = analyze("Recruiter at Amazon here, interview next week.", sender="jobs@amaz0n-careers.com")
    assert any(f.rule_id == "domain_mismatch" and f.risk == "high" for f in r.findings)


def test_all_findings_cite_real_lines():
    r = analyze(FORM + "\n" + FEE, sender="x@gmail.com")
    ids = {i for i, _ in r.lines}
    assert r.findings and all(f.verified and set(f.line_ids) <= ids for f in r.findings)


def test_domain_age_with_fake_fetcher_no_network():
    now = datetime(2026, 11, 1, tzinfo=timezone.utc)
    fetch = lambda d: datetime(2026, 10, 20, tzinfo=timezone.utc)
    r = analyze("Recruiter here.", sender="a@fresh-jobs.com", lookup=True, fetcher=fetch, now=now)
    assert any(f.rule_id == "new_domain" and f.risk == "high" for f in r.findings)


def test_lookup_failure_is_not_a_finding():
    r = analyze("Recruiter here.", sender="a@old-co.com", lookup=True, fetcher=lambda d: None)
    assert not any(f.rule_id == "new_domain" for f in r.findings)


def test_scoring_levels():
    low = [Finding("a", "b", "low", [1], rule_id="a")]
    med = [Finding("a", "b", "medium", [1], rule_id="a"), Finding("c", "d", "low", [1], rule_id="c")]
    assert score([])["level"] == "low"
    assert score(low)["level"] == "low"
    assert score(med)["level"] == "medium"
    assert score([Finding("x", "y", "high", [1], rule_id="x")])["level"] == "high"
    assert "not a verdict" in score([])["disclaimer"]


def test_empty_and_huge_input():
    assert analyze("").result["level"] == "low"
    assert analyze("hello " * 200000).result["level"] == "low"


def test_eval_math():
    rows = [{"text": FEE, "label": "scam"}, {"text": "Hello there.", "label": "scam"},
            {"text": AMAZON, "label": "legit"}, {"text": "x", "label": "unclear"}]
    r = evaluate(rows)
    assert (r["n_scam"], r["n_legit"]) == (2, 1)
    assert r["scam_recall"] == 0.5 and r["false_alarm_rate"] == 0.0
    assert r["warnings"]


def test_classifier_needs_data_and_trains():
    import pytest
    from checker import classifier
    with pytest.raises(classifier.NotEnoughData):
        classifier.train(["a"], ["scam"])
    texts = [FEE, CHECK, FORM, REG, "pay fee now send check"] + [AMAZON, RECRUITER, "Interview Tuesday 3pm on Zoom.",
             "Thanks for applying, we will be in touch.", "Your interview is confirmed with the hiring team."]
    labels = ["scam"] * 5 + ["legit"] * 5
    m = classifier.train(texts, labels)
    assert classifier.predict_proba(m, FEE) > classifier.predict_proba(m, AMAZON)


def test_web_roundtrip():
    from checker.web import make_server
    srv = make_server(0)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert b"Scam checker" in urllib.request.urlopen(f"http://127.0.0.1:{port}/").read()
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/check",
                                     data=json.dumps({"text": FEE}).encode(), method="POST")
        d = json.loads(urllib.request.urlopen(req).read())
        assert d["result"]["level"] == "high"
    finally:
        srv.shutdown()
