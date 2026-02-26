"""Tests for data models."""

from kubeshield.models import Finding, RuleMetadata, ScanResult, Severity, Category


class TestSeverity:
    def test_weight_ordering(self):
        assert Severity.CRITICAL.weight > Severity.HIGH.weight
        assert Severity.HIGH.weight > Severity.MEDIUM.weight
        assert Severity.MEDIUM.weight > Severity.LOW.weight
        assert Severity.LOW.weight > Severity.INFO.weight

    def test_color_returns_string(self):
        for sev in Severity:
            assert isinstance(sev.color, str)

    def test_icon_returns_string(self):
        for sev in Severity:
            assert isinstance(sev.icon, str)


class TestScanResult:
    def _make_finding(self, severity: Severity) -> Finding:
        rule = RuleMetadata(
            rule_id="TEST-001",
            name="Test rule",
            description="A test",
            severity=severity,
            category=Category.SECURITY,
        )
        return Finding(
            rule=rule,
            resource_name="test",
            resource_kind="Pod",
            namespace="default",
            file_path="test.yaml",
        )

    def test_empty_result_passes(self):
        result = ScanResult()
        assert result.passed is True
        assert result.score == 100
        assert result.total_findings == 0

    def test_critical_finding_fails(self):
        result = ScanResult(
            resources_scanned=1,
            findings=[self._make_finding(Severity.CRITICAL)],
        )
        assert result.passed is False
        assert result.critical_count == 1

    def test_high_finding_fails(self):
        result = ScanResult(
            resources_scanned=1,
            findings=[self._make_finding(Severity.HIGH)],
        )
        assert result.passed is False

    def test_medium_finding_passes(self):
        result = ScanResult(
            resources_scanned=1,
            findings=[self._make_finding(Severity.MEDIUM)],
        )
        assert result.passed is True

    def test_by_severity_groups_correctly(self):
        result = ScanResult(
            findings=[
                self._make_finding(Severity.HIGH),
                self._make_finding(Severity.HIGH),
                self._make_finding(Severity.LOW),
            ]
        )
        grouped = result.by_severity()
        assert len(grouped[Severity.HIGH]) == 2
        assert len(grouped[Severity.LOW]) == 1

    def test_score_decreases_with_findings(self):
        empty = ScanResult(resources_scanned=5)
        with_findings = ScanResult(
            resources_scanned=5,
            findings=[self._make_finding(Severity.CRITICAL)] * 3,
        )
        assert empty.score > with_findings.score


class TestFinding:
    def test_location_with_container(self):
        rule = RuleMetadata(
            rule_id="T-001",
            name="Test",
            description="Test",
            severity=Severity.LOW,
            category=Category.SECURITY,
        )
        finding = Finding(
            rule=rule,
            resource_name="my-pod",
            resource_kind="Pod",
            namespace="kube-system",
            file_path="test.yaml",
            container_name="nginx",
        )
        assert finding.location == "kube-system/Pod/my-pod/container:nginx"

    def test_location_without_namespace(self):
        rule = RuleMetadata(
            rule_id="T-001",
            name="Test",
            description="Test",
            severity=Severity.LOW,
            category=Category.SECURITY,
        )
        finding = Finding(
            rule=rule,
            resource_name="my-pod",
            resource_kind="Pod",
            namespace="",
            file_path="test.yaml",
        )
        assert finding.location == "Pod/my-pod"
