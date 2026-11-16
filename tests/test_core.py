from checker import Finding, split_lines, verify


def test_split_numbers_lines():
    assert split_lines("a\n\n b") == [(1, "a"), (2, "b")]


def test_verify_drops_fabricated_citation():
    kept, stats = verify([Finding("x", "y", line_ids=[9], quote="made up")], [(1, "hello there")])
    assert kept == [] and stats["dropped_no_valid_citation"] == 1


def test_verify_marks_wrong_quote_unverified():
    lines = [(1, "Please send your resume."), (2, "We pay weekly.")]
    kept, _ = verify([Finding("fee", "y", line_ids=[2], quote="pay a fee")], lines)
    assert kept[0].verified is False


def test_verify_accepts_exact_quote():
    kept, _ = verify([Finding("pay", "y", line_ids=[1], quote="send your resume")],
                     [(1, "Please send your resume.")])
    assert kept[0].verified is True
