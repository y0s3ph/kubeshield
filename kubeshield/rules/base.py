"""Base rule class and rule registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from kubeshield.models import Finding, Resource, RuleMetadata

registry: list[type[Rule]] = []


class Rule(ABC):
    """Base class for all security rules."""

    meta: ClassVar[RuleMetadata]
    workload_kinds: ClassVar[set[str]] = {
        "Pod",
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "ReplicaSet",
        "Job",
        "CronJob",
    }

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if hasattr(cls, "meta"):
            registry.append(cls)

    @abstractmethod
    def check(self, resource: Resource) -> list[Finding]:
        ...

    def applies_to(self, resource: Resource) -> bool:
        return resource.kind in self.workload_kinds

    def _get_pod_spec(self, resource: Resource) -> dict | None:
        raw = resource.raw
        kind = resource.kind
        if kind == "Pod":
            return raw.get("spec", {})
        if kind == "CronJob":
            return (
                raw.get("spec", {})
                .get("jobTemplate", {})
                .get("spec", {})
                .get("template", {})
                .get("spec", {})
            )
        return raw.get("spec", {}).get("template", {}).get("spec", {})

    def _get_containers(self, resource: Resource) -> list[tuple[str, dict]]:
        """Return (container_type, container_spec) pairs."""
        pod_spec = self._get_pod_spec(resource)
        if not pod_spec:
            return []
        containers = []
        for c in pod_spec.get("containers", []):
            containers.append(("container", c))
        for c in pod_spec.get("initContainers", []):
            containers.append(("initContainer", c))
        return containers
