"""Tests for the scanner engine."""

from pathlib import Path

from kubeshield.scanner import Scanner


class TestScanner:
    def test_scan_insecure_file(self, fixtures_dir):
        scanner = Scanner()
        result = scanner.scan([fixtures_dir / "insecure-pod.yaml"])
        assert result.files_scanned == 1
        assert result.resources_scanned == 1
        assert result.total_findings > 0
        assert result.passed is False

    def test_scan_secure_file(self, fixtures_dir):
        scanner = Scanner()
        result = scanner.scan([fixtures_dir / "secure-pod.yaml"])
        assert result.files_scanned == 1
        assert result.resources_scanned == 1
        assert result.critical_count == 0
        assert result.high_count == 0

    def test_scan_directory(self, fixtures_dir):
        scanner = Scanner()
        result = scanner.scan([fixtures_dir])
        assert result.files_scanned >= 2
        assert result.resources_scanned >= 2

    def test_scan_multi_document(self, fixtures_dir):
        scanner = Scanner()
        result = scanner.scan([fixtures_dir / "multi-doc.yaml"])
        assert result.resources_scanned == 2

    def test_filter_by_severity(self, fixtures_dir):
        scanner_all = Scanner()
        result_all = scanner_all.scan([fixtures_dir / "insecure-pod.yaml"])

        scanner_critical = Scanner(severities=["CRITICAL"])
        result_critical = scanner_critical.scan([fixtures_dir / "insecure-pod.yaml"])

        assert result_critical.total_findings < result_all.total_findings
        assert all(
            f.rule.severity.value == "CRITICAL" for f in result_critical.findings
        )

    def test_filter_by_rule_id(self, fixtures_dir):
        scanner = Scanner(rule_ids=["KS-SEC-002"])
        result = scanner.scan([fixtures_dir / "insecure-pod.yaml"])
        assert all(f.rule.rule_id == "KS-SEC-002" for f in result.findings)

    def test_nonexistent_path(self):
        scanner = Scanner()
        result = scanner.scan([Path("/nonexistent/path")])
        assert len(result.errors) == 1

    def test_invalid_yaml(self, tmp_path):
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text(": invalid: yaml: [")
        scanner = Scanner()
        result = scanner.scan([bad_file])
        assert len(result.errors) == 1

    def test_non_k8s_yaml_ignored(self, tmp_path):
        other_file = tmp_path / "config.yaml"
        other_file.write_text("database:\n  host: localhost\n  port: 5432\n")
        scanner = Scanner()
        result = scanner.scan([other_file])
        assert result.resources_scanned == 0
        assert result.total_findings == 0
