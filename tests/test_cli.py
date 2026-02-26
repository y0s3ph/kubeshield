"""Tests for the CLI."""

from click.testing import CliRunner

from kubeshield.cli import main


class TestCLI:
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "kubeshield" in result.output

    def test_scan_insecure(self, fixtures_dir):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(fixtures_dir / "insecure-pod.yaml")])
        assert result.exit_code == 1

    def test_scan_secure(self, fixtures_dir):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(fixtures_dir / "secure-pod.yaml")])
        assert result.exit_code == 0

    def test_scan_json_output(self, fixtures_dir):
        runner = CliRunner()
        result = runner.invoke(
            main, ["scan", "--json", str(fixtures_dir / "insecure-pod.yaml")]
        )
        assert '"kubeshield_version"' in result.output
        assert '"findings"' in result.output

    def test_scan_json_file_output(self, fixtures_dir, tmp_path):
        output_file = tmp_path / "report.json"
        runner = CliRunner()
        runner.invoke(
            main,
            ["scan", "-o", str(output_file), str(fixtures_dir / "insecure-pod.yaml")],
        )
        assert output_file.exists()
        content = output_file.read_text()
        assert '"findings"' in content

    def test_scan_severity_filter(self, fixtures_dir):
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "-s", "CRITICAL", "--json", str(fixtures_dir / "insecure-pod.yaml")],
        )
        assert result.exit_code == 1
        assert "CRITICAL" in result.output

    def test_scan_fail_on_low(self, fixtures_dir):
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--fail-on", "low", str(fixtures_dir / "insecure-pod.yaml")],
        )
        assert result.exit_code == 1

    def test_list_rules(self):
        runner = CliRunner()
        result = runner.invoke(main, ["rules"])
        assert result.exit_code == 0
        assert "KS-SEC" in result.output
        assert "KS-REL" in result.output
