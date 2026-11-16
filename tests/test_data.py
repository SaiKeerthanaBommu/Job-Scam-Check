import csv
import tempfile
from pathlib import Path

from scripts.check_data import check, COLUMNS
from scripts.make_split import make_split


def _write(rows):
    f = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="", encoding="utf-8")
    w = csv.DictWriter(f, fieldnames=COLUMNS)
    w.writeheader()
    w.writerows(rows)
    f.close()
    return Path(f.name)


def row(**kw):
    base = dict(id="a", text="A message that is long enough to count as text.", label="",
                red_flags="", how_verified="", source="own inbox")
    base.update(kw)
    return base


def test_repo_data_file_is_clean():
    assert check() == []


def test_flags_email_phone_and_link():
    p = _write([row(text="Write to jobs@example.com or call 555-123-4567 at https://x.example")])
    problems = " ".join(check(p))
    assert "email address" in problems and "phone number" in problems and "web link" in problems


def test_rejects_bad_label_and_duplicate_id():
    p = _write([row(id="a", label="maybe"), row(id="a")])
    problems = " ".join(check(p))
    assert "label must be" in problems and "duplicate" in problems


def test_scam_label_requires_verification_note():
    p = _write([row(label="scam")])
    assert any("how_verified" in x for x in check(p))


def test_split_is_stable_and_stratified():
    rows = [dict(id=f"s{i}", label="scam") for i in range(10)] + [dict(id=f"l{i}", label="legit") for i in range(10)]
    a, b = make_split(rows), make_split(rows)
    assert a == b
    for lab in ("s", "l"):
        assert {v for k, v in a.items() if k.startswith(lab)} == {"train", "test"}
