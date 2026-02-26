"""Security-focused rules."""

from __future__ import annotations

from kubeshield.models import Category, Finding, Resource, RuleMetadata, Severity
from kubeshield.rules.base import Rule


class RunAsRoot(Rule):
    meta = RuleMetadata(
        rule_id="KS-SEC-001",
        name="Container runs as root",
        description="Containers should not run as root user. Running as root grants "
        "unnecessary privileges that can be exploited if the container is compromised.",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        cis_benchmark="5.2.6",
        remediation="Set `securityContext.runAsNonRoot: true` and specify a non-zero "
        "`runAsUser` in the container or pod security context.",
    )

    def check(self, resource: Resource) -> list[Finding]:
        findings = []
        pod_spec = self._get_pod_spec(resource)
        if not pod_spec:
            return findings

        pod_sc = pod_spec.get("securityContext", {})
        pod_run_as_non_root = pod_sc.get("runAsNonRoot", False)
        pod_run_as_user = pod_sc.get("runAsUser")

        for _, container in self._get_containers(resource):
            sc = container.get("securityContext", {})
            run_as_non_root = sc.get("runAsNonRoot", pod_run_as_non_root)
            run_as_user = sc.get("runAsUser", pod_run_as_user)

            if not run_as_non_root and (run_as_user is None or run_as_user == 0):
                findings.append(
                    Finding(
                        rule=self.meta,
                        resource_name=resource.name,
                        resource_kind=resource.kind,
                        namespace=resource.namespace,
                        file_path=resource.file_path,
                        container_name=container.get("name"),
                        details="Container may run as root (UID 0)",
                    )
                )
        return findings


class PrivilegedContainer(Rule):
    meta = RuleMetadata(
        rule_id="KS-SEC-002",
        name="Privileged container",
        description="Privileged containers have full access to the host, bypassing "
        "almost all security boundaries. This is rarely necessary and extremely dangerous.",
        severity=Severity.CRITICAL,
        category=Category.SECURITY,
        cis_benchmark="5.2.1",
        remediation="Set `securityContext.privileged: false` or remove the privileged flag.",
    )

    def check(self, resource: Resource) -> list[Finding]:
        findings = []
        for _, container in self._get_containers(resource):
            sc = container.get("securityContext", {})
            if sc.get("privileged", False):
                findings.append(
                    Finding(
                        rule=self.meta,
                        resource_name=resource.name,
                        resource_kind=resource.kind,
                        namespace=resource.namespace,
                        file_path=resource.file_path,
                        container_name=container.get("name"),
                        details="Container is running in privileged mode",
                    )
                )
        return findings


class ReadOnlyRootFilesystem(Rule):
    meta = RuleMetadata(
        rule_id="KS-SEC-003",
        name="Writable root filesystem",
        description="A writable root filesystem allows attackers to write malicious "
        "binaries or modify system files if the container is compromised.",
        severity=Severity.MEDIUM,
        category=Category.SECURITY,
        cis_benchmark="5.2.4",
        remediation="Set `securityContext.readOnlyRootFilesystem: true` and use "
        "emptyDir volumes for any writable paths.",
    )

    def check(self, resource: Resource) -> list[Finding]:
        findings = []
        for _, container in self._get_containers(resource):
            sc = container.get("securityContext", {})
            if not sc.get("readOnlyRootFilesystem", False):
                findings.append(
                    Finding(
                        rule=self.meta,
                        resource_name=resource.name,
                        resource_kind=resource.kind,
                        namespace=resource.namespace,
                        file_path=resource.file_path,
                        container_name=container.get("name"),
                        details="Root filesystem is writable",
                    )
                )
        return findings


class CapabilitiesNotDropped(Rule):
    meta = RuleMetadata(
        rule_id="KS-SEC-004",
        name="Linux capabilities not dropped",
        description="Containers inherit a default set of Linux capabilities. Dropping "
        "all capabilities and adding only those required reduces the attack surface.",
        severity=Severity.MEDIUM,
        category=Category.SECURITY,
        cis_benchmark="5.2.7",
        remediation="Set `securityContext.capabilities.drop: ['ALL']` and add only "
        "required capabilities with `add`.",
    )

    def check(self, resource: Resource) -> list[Finding]:
        findings = []
        for _, container in self._get_containers(resource):
            sc = container.get("securityContext", {})
            caps = sc.get("capabilities", {})
            drop = [c.upper() for c in caps.get("drop", [])]
            if "ALL" not in drop:
                findings.append(
                    Finding(
                        rule=self.meta,
                        resource_name=resource.name,
                        resource_kind=resource.kind,
                        namespace=resource.namespace,
                        file_path=resource.file_path,
                        container_name=container.get("name"),
                        details="Capabilities are not dropped (missing drop: ['ALL'])",
                    )
                )
        return findings


class AllowPrivilegeEscalation(Rule):
    meta = RuleMetadata(
        rule_id="KS-SEC-005",
        name="Privilege escalation allowed",
        description="Containers with allowPrivilegeEscalation can gain more privileges "
        "than their parent process, enabling potential breakout attacks.",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        cis_benchmark="5.2.5",
        remediation="Set `securityContext.allowPrivilegeEscalation: false`.",
    )

    def check(self, resource: Resource) -> list[Finding]:
        findings = []
        for _, container in self._get_containers(resource):
            sc = container.get("securityContext", {})
            if sc.get("allowPrivilegeEscalation", True):
                findings.append(
                    Finding(
                        rule=self.meta,
                        resource_name=resource.name,
                        resource_kind=resource.kind,
                        namespace=resource.namespace,
                        file_path=resource.file_path,
                        container_name=container.get("name"),
                        details="Privilege escalation is not explicitly disabled",
                    )
                )
        return findings


class HostNamespace(Rule):
    meta = RuleMetadata(
        rule_id="KS-SEC-006",
        name="Host namespace sharing",
        description="Sharing host namespaces (PID, network, IPC) breaks container "
        "isolation and can expose sensitive host-level information.",
        severity=Severity.CRITICAL,
        category=Category.SECURITY,
        cis_benchmark="5.2.2",
        remediation="Remove `hostPID`, `hostNetwork`, and `hostIPC` or set them to false.",
    )

    def check(self, resource: Resource) -> list[Finding]:
        findings = []
        pod_spec = self._get_pod_spec(resource)
        if not pod_spec:
            return findings

        for field, label in [
            ("hostPID", "host PID namespace"),
            ("hostNetwork", "host network namespace"),
            ("hostIPC", "host IPC namespace"),
        ]:
            if pod_spec.get(field, False):
                findings.append(
                    Finding(
                        rule=self.meta,
                        resource_name=resource.name,
                        resource_kind=resource.kind,
                        namespace=resource.namespace,
                        file_path=resource.file_path,
                        details=f"Pod is sharing {label}",
                    )
                )
        return findings


class LatestTag(Rule):
    meta = RuleMetadata(
        rule_id="KS-SEC-007",
        name="Image uses 'latest' tag",
        description="Using the 'latest' tag or no tag makes deployments "
        "non-deterministic and hinders rollback capabilities.",
        severity=Severity.MEDIUM,
        category=Category.SECURITY,
        remediation="Use a specific, immutable image tag or digest (e.g., "
        "`image:v1.2.3` or `image@sha256:...`).",
    )

    def check(self, resource: Resource) -> list[Finding]:
        findings = []
        for _, container in self._get_containers(resource):
            image = container.get("image", "")
            if ":" not in image or image.endswith(":latest"):
                findings.append(
                    Finding(
                        rule=self.meta,
                        resource_name=resource.name,
                        resource_kind=resource.kind,
                        namespace=resource.namespace,
                        file_path=resource.file_path,
                        container_name=container.get("name"),
                        details=f"Image '{image}' uses 'latest' or unspecified tag",
                    )
                )
        return findings


class SeccompProfile(Rule):
    meta = RuleMetadata(
        rule_id="KS-SEC-008",
        name="Missing Seccomp profile",
        description="Without a Seccomp profile, containers have access to all Linux "
        "syscalls, increasing the attack surface.",
        severity=Severity.LOW,
        category=Category.SECURITY,
        cis_benchmark="5.7.2",
        remediation="Set `securityContext.seccompProfile.type: RuntimeDefault` or use "
        "a custom Seccomp profile.",
    )

    def check(self, resource: Resource) -> list[Finding]:
        findings = []
        pod_spec = self._get_pod_spec(resource)
        if not pod_spec:
            return findings

        pod_sc = pod_spec.get("securityContext", {})
        pod_seccomp = pod_sc.get("seccompProfile", {}).get("type")

        for _, container in self._get_containers(resource):
            sc = container.get("securityContext", {})
            seccomp = sc.get("seccompProfile", {}).get("type", pod_seccomp)
            if not seccomp:
                findings.append(
                    Finding(
                        rule=self.meta,
                        resource_name=resource.name,
                        resource_kind=resource.kind,
                        namespace=resource.namespace,
                        file_path=resource.file_path,
                        container_name=container.get("name"),
                        details="No Seccomp profile configured",
                    )
                )
        return findings


class ServiceAccountToken(Rule):
    meta = RuleMetadata(
        rule_id="KS-SEC-009",
        name="Auto-mounted service account token",
        description="Service account tokens are automatically mounted in pods and can "
        "be used to interact with the Kubernetes API. Most workloads don't need this.",
        severity=Severity.LOW,
        category=Category.SECURITY,
        cis_benchmark="5.1.6",
        remediation="Set `automountServiceAccountToken: false` in the pod spec.",
    )

    def check(self, resource: Resource) -> list[Finding]:
        findings = []
        pod_spec = self._get_pod_spec(resource)
        if not pod_spec:
            return findings

        if pod_spec.get("automountServiceAccountToken", True):
            findings.append(
                Finding(
                    rule=self.meta,
                    resource_name=resource.name,
                    resource_kind=resource.kind,
                    namespace=resource.namespace,
                    file_path=resource.file_path,
                    details="Service account token is auto-mounted",
                )
            )
        return findings
