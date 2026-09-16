from aicsec.sast_patterns import scan_path as sast_scan
from aicsec.secret_scan import scan_text, shannon_entropy


def test_entropy_of_repeated_chars_is_low():
    assert shannon_entropy("aaaaaaaa") < 1.0


def test_detects_password_assignment():
    findings = scan_text('password = "hunter2x"\n', "demo.py")
    assert any(item.rule == "password_assign" for item in findings)


def test_sast_finds_sample_sql():
    from pathlib import Path

    sample = Path(__file__).resolve().parents[1] / "samples" / "vulnerable_app.py"
    hits = sast_scan(sample)
    assert any(item.rule_id == "sql-string-concat" for item in hits)
