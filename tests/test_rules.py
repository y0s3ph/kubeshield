"""Tests for security rules."""

from kubeshield.models import Resource
from kubeshield.rules.security import (
    AllowPrivilegeEscalation,
    CapabilitiesNotDropped,
    HostNamespace,
    LatestTag,
    PrivilegedContainer,
    ReadOnlyRootFilesystem,
    RunAsRoot,
    SeccompProfile,
    ServiceAccountToken,
)
from kubeshield.rules.reliability import (
    MissingLivenessProbe,
    MissingReadinessProbe,
    SingleReplica,
)
from kubeshield.rules.resources import MissingResourceLimits, MissingResourceRequests
from kubeshield.rules.networking import DefaultNamespace, HostPort


def _make_resource(raw: dict) -> Resource:
    metadata = raw.get("metadata", {})
    return Resource(
        api_version=raw.get("apiVersion", "v1"),
        kind=raw.get("kind", "Pod"),
        name=metadata.get("name", "test"),
        namespace=metadata.get("namespace", ""),
        raw=raw,
    )


class TestRunAsRoot:
    def test_detects_missing_non_root(self, insecure_pod):
        findings = RunAsRoot().check(_make_resource(insecure_pod))
        assert len(findings) == 1
        assert "root" in findings[0].details.lower()

    def test_passes_with_non_root(self, secure_pod):
        findings = RunAsRoot().check(_make_resource(secure_pod))
        assert len(findings) == 0


class TestPrivilegedContainer:
    def test_detects_privileged(self, insecure_pod):
        findings = PrivilegedContainer().check(_make_resource(insecure_pod))
        assert len(findings) == 1

    def test_passes_non_privileged(self, secure_pod):
        findings = PrivilegedContainer().check(_make_resource(secure_pod))
        assert len(findings) == 0


class TestReadOnlyRootFilesystem:
    def test_detects_writable(self, insecure_pod):
        findings = ReadOnlyRootFilesystem().check(_make_resource(insecure_pod))
        assert len(findings) == 1

    def test_passes_readonly(self, secure_pod):
        findings = ReadOnlyRootFilesystem().check(_make_resource(secure_pod))
        assert len(findings) == 0


class TestCapabilitiesNotDropped:
    def test_detects_missing_drop(self, insecure_pod):
        findings = CapabilitiesNotDropped().check(_make_resource(insecure_pod))
        assert len(findings) == 1

    def test_passes_with_drop_all(self, secure_pod):
        findings = CapabilitiesNotDropped().check(_make_resource(secure_pod))
        assert len(findings) == 0


class TestAllowPrivilegeEscalation:
    def test_detects_escalation(self, insecure_pod):
        findings = AllowPrivilegeEscalation().check(_make_resource(insecure_pod))
        assert len(findings) == 1

    def test_passes_no_escalation(self, secure_pod):
        findings = AllowPrivilegeEscalation().check(_make_resource(secure_pod))
        assert len(findings) == 0


class TestHostNamespace:
    def test_detects_host_pid(self, insecure_pod):
        findings = HostNamespace().check(_make_resource(insecure_pod))
        assert len(findings) >= 1
        details = [f.details for f in findings]
        assert any("PID" in d for d in details)

    def test_passes_no_host_ns(self, secure_pod):
        findings = HostNamespace().check(_make_resource(secure_pod))
        assert len(findings) == 0


class TestLatestTag:
    def test_detects_latest(self, insecure_pod):
        findings = LatestTag().check(_make_resource(insecure_pod))
        assert len(findings) == 1

    def test_passes_pinned_digest(self, secure_pod):
        findings = LatestTag().check(_make_resource(secure_pod))
        assert len(findings) == 0


class TestSeccompProfile:
    def test_detects_missing_seccomp(self, insecure_pod):
        findings = SeccompProfile().check(_make_resource(insecure_pod))
        assert len(findings) == 1

    def test_passes_with_seccomp(self, secure_pod):
        findings = SeccompProfile().check(_make_resource(secure_pod))
        assert len(findings) == 0


class TestServiceAccountToken:
    def test_detects_auto_mount(self, insecure_pod):
        findings = ServiceAccountToken().check(_make_resource(insecure_pod))
        assert len(findings) == 1

    def test_passes_disabled(self, secure_pod):
        findings = ServiceAccountToken().check(_make_resource(secure_pod))
        assert len(findings) == 0


class TestMissingLivenessProbe:
    def test_detects_missing(self, insecure_pod):
        findings = MissingLivenessProbe().check(_make_resource(insecure_pod))
        assert len(findings) == 1

    def test_passes_with_probe(self, secure_pod):
        findings = MissingLivenessProbe().check(_make_resource(secure_pod))
        assert len(findings) == 0


class TestMissingReadinessProbe:
    def test_detects_missing(self, insecure_pod):
        findings = MissingReadinessProbe().check(_make_resource(insecure_pod))
        assert len(findings) == 1

    def test_passes_with_probe(self, secure_pod):
        findings = MissingReadinessProbe().check(_make_resource(secure_pod))
        assert len(findings) == 0


class TestSingleReplica:
    def test_detects_single_replica(self, insecure_deployment):
        findings = SingleReplica().check(_make_resource(insecure_deployment))
        assert len(findings) == 1

    def test_passes_multiple_replicas(self):
        raw = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "good", "namespace": "prod"},
            "spec": {"replicas": 3},
        }
        findings = SingleReplica().check(_make_resource(raw))
        assert len(findings) == 0


class TestMissingResourceLimits:
    def test_detects_missing_limits(self, insecure_pod):
        findings = MissingResourceLimits().check(_make_resource(insecure_pod))
        assert len(findings) == 1

    def test_passes_with_limits(self, secure_pod):
        findings = MissingResourceLimits().check(_make_resource(secure_pod))
        assert len(findings) == 0


class TestMissingResourceRequests:
    def test_detects_missing_requests(self, insecure_pod):
        findings = MissingResourceRequests().check(_make_resource(insecure_pod))
        assert len(findings) == 1

    def test_passes_with_requests(self, secure_pod):
        findings = MissingResourceRequests().check(_make_resource(secure_pod))
        assert len(findings) == 0


class TestHostPort:
    def test_detects_hostport(self, insecure_deployment):
        findings = HostPort().check(_make_resource(insecure_deployment))
        assert len(findings) == 1

    def test_passes_no_hostport(self, secure_pod):
        findings = HostPort().check(_make_resource(secure_pod))
        assert len(findings) == 0


class TestDefaultNamespace:
    def test_detects_default(self, insecure_pod):
        findings = DefaultNamespace().check(_make_resource(insecure_pod))
        assert len(findings) == 1

    def test_passes_non_default(self, secure_pod):
        findings = DefaultNamespace().check(_make_resource(secure_pod))
        assert len(findings) == 0
