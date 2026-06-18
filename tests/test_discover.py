"""AI-discovery parsing + tiering, with the LLM stubbed so the test is offline
and deterministic. Confirms: JSON -> Finding mapping, confidence filtering,
dedupe against scanner findings, and the off/no-key short-circuit."""
from patchwright import discover, llm
from patchwright.models import Finding, FindingKind, Severity


def test_off_mode_returns_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "available", lambda: True)
    assert discover.discover(str(tmp_path), [], mode="off") == []


def test_no_api_key_short_circuits(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "available", lambda: False)
    assert discover.discover(str(tmp_path), [], mode="deep") == []


def test_parses_and_filters_by_confidence(tmp_path, monkeypatch):
    (tmp_path / "svc.py").write_text("def handler(req):\n    return run(req)\n")
    fake = [
        {"line": 2, "end_line": 2, "vuln_class": "command-injection",
         "title": "unsanitized input to run()", "severity": "high",
         "explanation": "req flows to run() unchecked", "confidence": 0.9},
        {"line": 1, "vuln_class": "noise", "title": "maybe",
         "severity": "low", "explanation": "low conf", "confidence": 0.2},
    ]
    monkeypatch.setattr(llm, "available", lambda: True)
    monkeypatch.setattr(discover.llm, "complete_json", lambda *a, **k: fake)

    out = discover.discover(str(tmp_path), [], mode="deep", confirm=False)
    assert len(out) == 1                      # low-confidence one filtered out
    f = out[0]
    assert f.scanner == "ai-discovery"
    assert f.rule_id == "ai.command-injection"
    assert f.kind == FindingKind.CODE
    assert f.severity == Severity.HIGH
    assert f.start_line == 2
    assert f.confirmed is False               # confirm=False -> stays suspected


def test_dedupes_against_scanner_findings(tmp_path, monkeypatch):
    (tmp_path / "svc.py").write_text("x = eval(input())\n")
    existing = [Finding(kind=FindingKind.CODE, rule_id="py.eval", title="eval",
                        severity=Severity.HIGH, file_path="svc.py", start_line=1,
                        end_line=1, scanner="semgrep")]
    fake = [{"line": 1, "vuln_class": "code-injection", "title": "eval",
             "severity": "high", "explanation": "eval of input", "confidence": 0.9}]
    monkeypatch.setattr(llm, "available", lambda: True)
    monkeypatch.setattr(discover.llm, "complete_json", lambda *a, **k: fake)

    # AI flags the same line semgrep already owns -> deduped away
    out = discover.discover(str(tmp_path), existing, mode="augment", confirm=False)
    assert out == []
