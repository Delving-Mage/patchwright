"""Farm two-way client: resolve/enrich + idempotent evidence-rich sync, with the
HTTP layer stubbed so tests are offline and deterministic."""
from patchwright.farm import FarmClient
from patchwright.models import Finding, FindingKind, Severity, Patch
from patchwright.pipeline import Report


def _finding(scanner="semgrep", file="A.java", line=10, rule="r"):
    return Finding(kind=FindingKind.CODE, rule_id=rule, title="t",
                   severity=Severity.HIGH, file_path=file, start_line=line,
                   end_line=line, scanner=scanner)


def _client():
    return FarmClient(base_url="https://farm.internal/api", token="tok")


def test_from_env_disabled_without_url(monkeypatch):
    monkeypatch.delenv("FARM_API_URL", raising=False)
    assert FarmClient.from_env() is None


def test_resolve_enriches_findings(monkeypatch):
    f = _finding()
    fp = f.fingerprint()
    c = _client()
    monkeypatch.setattr(c, "_post", lambda path, payload: {
        "results": [{"key": fp, "farm_id": "FARM-123",
                     "status": "open", "owner": "team-sec"}]})
    c.resolve([f])
    assert f.farm_id == "FARM-123"
    assert f.farm_status == "open"
    assert f.suppressed is False
    assert f.farm_meta.get("owner") == "team-sec"


def test_resolve_marks_suppressed(monkeypatch):
    f = _finding()
    c = _client()
    monkeypatch.setattr(c, "_post", lambda path, payload: {
        "results": [{"key": f.fingerprint(), "farm_id": "FARM-9",
                     "status": "accepted_risk"}]})
    c.resolve([f])
    assert f.suppressed is True


def test_resolve_accepts_farm_ids_map_shape(monkeypatch):
    f = _finding()
    c = _client()
    monkeypatch.setattr(c, "_post",
                        lambda path, payload: {"farm_ids": {f.fingerprint(): "FARM-7"}})
    c.resolve([f])
    assert f.farm_id == "FARM-7"


def test_resolve_request_shape(monkeypatch):
    f = _finding()
    captured = {}
    c = _client()
    def fake_post(path, payload):
        captured["path"], captured["payload"] = path, payload
        return {"results": []}
    monkeypatch.setattr(c, "_post", fake_post)
    c.resolve([f])
    assert captured["path"] == "/findings/resolve"
    item = captured["payload"]["findings"][0]
    assert item["key"] == f.fingerprint()
    assert item["rule_id"] == "r" and item["severity"] == "HIGH"


def test_sync_statuses_and_suppressed_skip(monkeypatch):
    fixed = _finding(file="Fixed.java", rule="sqli")
    new = _finding(file="New.java", scanner="ai-discovery", rule="ai.ssrf")
    supp = _finding(file="Supp.java", rule="x")
    supp.suppressed = True
    fixed.farm_id = "FARM-1"

    report = Report()
    report.findings = [fixed, new, supp]
    report.patches = [Patch(finding_fp=fixed.fingerprint(), file_path="Fixed.java",
                            original="a", patched="b", rationale="fix",
                            validated=True, validation_evidence=["re-scan clean", "tests passed"],
                            confidence=0.9)]
    report.pr_url = "https://bitbucket/pr/1"

    c = _client()
    captured = {}
    monkeypatch.setattr(c, "_post",
                        lambda path, payload: captured.setdefault("u", payload["updates"]) or {})
    res = c.sync(report)

    updates = {u["key"]: u for u in captured["u"]}
    assert supp.fingerprint() not in updates          # suppressed -> skipped
    assert updates[fixed.fingerprint()]["status"] == "FIXED_VALIDATED"
    assert updates[fixed.fingerprint()]["pr_url"] == "https://bitbucket/pr/1"
    assert "tests passed" in updates[fixed.fingerprint()]["evidence"]
    assert updates[new.fingerprint()]["status"] == "NEW"
    assert res["synced"] == 2


def test_sync_dry_run_does_not_post(monkeypatch):
    f = _finding()
    report = Report()
    report.findings = [f]
    c = FarmClient(base_url="https://farm.internal/api", dry_run=True)
    called = {"n": 0}
    monkeypatch.setattr(c, "_post", lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    res = c.sync(report)
    assert res["dry_run"] is True
    assert called["n"] == 0
