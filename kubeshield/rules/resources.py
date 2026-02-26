"""Resource management rules."""

from __future__ import annotations

from kubeshield.models import Category, Finding, Resource, RuleMetadata, Severity
from kubeshield.rules.base import Rule


class MissingResourceLimits(Rule):
    meta = RuleMetadata(
        rule_id="KS-RES-001",
        name="Missing resource limits",
        description="Without resource limits, a container can consume all available "
        "CPU and memory on a node, causing resource starvation for other workloads.",
        severity=Severity.HIGH,
        category=Category.RESOURCES,
        cis_benchmark="5.4.1",
        remediation="Set `resources.limits.cpu` and `resources.limits.memory` for each container.",
    )

    def check(self, resource: Resource) -> list[Finding]:
        findings = []
        for _, container in self._get_containers(resource):
            resources = container.get("resources", {})
            limits = resources.get("limits", {})
            missing = []
            if "cpu" not in limits:
                missing.append("cpu")
            if "memory" not in limits:
                missing.append("memory")
            if missing:
                findings.append(
                    Finding(
                        rule=self.meta,
                        resource_name=resource.name,
                        resource_kind=resource.kind,
                        namespace=resource.namespace,
                        file_path=resource.file_path,
                        container_name=container.get("name"),
                        details=f"Missing limits for: {', '.join(missing)}",
                    )
                )
        return findings


class MissingResourceRequests(Rule):
    meta = RuleMetadata(
        rule_id="KS-RES-002",
        name="Missing resource requests",
        description="Without resource requests, the scheduler cannot make informed "
        "placement decisions and QoS guarantees are weakened.",
        severity=Severity.MEDIUM,
        category=Category.RESOURCES,
        remediation="Set `resources.requests.cpu` and `resources.requests.memory` for each container.",
    )

    def check(self, resource: Resource) -> list[Finding]:
        findings = []
        for _, container in self._get_containers(resource):
            resources = container.get("resources", {})
            requests = resources.get("requests", {})
            missing = []
            if "cpu" not in requests:
                missing.append("cpu")
            if "memory" not in requests:
                missing.append("memory")
            if missing:
                findings.append(
                    Finding(
                        rule=self.meta,
                        resource_name=resource.name,
                        resource_kind=resource.kind,
                        namespace=resource.namespace,
                        file_path=resource.file_path,
                        container_name=container.get("name"),
                        details=f"Missing requests for: {', '.join(missing)}",
                    )
                )
        return findings
