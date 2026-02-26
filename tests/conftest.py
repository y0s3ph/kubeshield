"""Shared fixtures for KubeShield tests."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def insecure_pod() -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "insecure-pod", "namespace": "default"},
        "spec": {
            "hostPID": True,
            "containers": [
                {
                    "name": "app",
                    "image": "nginx:latest",
                    "securityContext": {
                        "privileged": True,
                        "allowPrivilegeEscalation": True,
                    },
                }
            ],
        },
    }


@pytest.fixture
def secure_pod() -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "secure-pod", "namespace": "production"},
        "spec": {
            "automountServiceAccountToken": False,
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 10000,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [
                {
                    "name": "app",
                    "image": "nginx:1.27.3-alpine@sha256:abc123",
                    "resources": {
                        "requests": {"cpu": "100m", "memory": "128Mi"},
                        "limits": {"cpu": "500m", "memory": "256Mi"},
                    },
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True,
                        "capabilities": {"drop": ["ALL"]},
                    },
                    "livenessProbe": {"httpGet": {"path": "/healthz", "port": 8080}},
                    "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}},
                }
            ],
        },
    }


@pytest.fixture
def insecure_deployment() -> dict:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "vuln-deploy", "namespace": "default"},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "vuln"}},
            "template": {
                "metadata": {"labels": {"app": "vuln"}},
                "spec": {
                    "containers": [
                        {
                            "name": "web",
                            "image": "nginx",
                            "ports": [{"containerPort": 80, "hostPort": 8080}],
                        }
                    ]
                },
            },
        },
    }
