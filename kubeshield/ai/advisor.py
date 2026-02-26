"""AI-powered remediation advisor using OpenAI-compatible APIs."""

from __future__ import annotations

import os

from openai import OpenAI

from kubeshield.models import Finding, ScanResult

SYSTEM_PROMPT = """\
You are a Kubernetes security expert. Given a list of security findings \
from a manifest scan, provide a concise, actionable remediation plan. \
Group related issues together. For each group, provide:
1. A brief explanation of the risk
2. A YAML snippet showing the fix
3. Priority order for remediation

Be concise but precise. Use markdown formatting.\
"""


class AIAdvisor:
    def __init__(self, api_key: str | None = None, model: str = "gpt-4o-mini") -> None:
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self._model = model

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    def advise(self, result: ScanResult) -> str:
        if not self.available:
            return (
                "[dim]AI advisor unavailable — set OPENAI_API_KEY to get "
                "AI-powered remediation suggestions.[/dim]"
            )

        if not result.findings:
            return "No findings to analyze. Your manifests look secure!"

        prompt = self._build_prompt(result.findings)
        client = OpenAI(api_key=self._api_key)
        response = client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=2000,
        )
        return response.choices[0].message.content or "No response from AI advisor."

    def _build_prompt(self, findings: list[Finding]) -> str:
        lines = ["Analyze these Kubernetes security findings and provide a remediation plan:\n"]
        for i, f in enumerate(findings, 1):
            lines.append(
                f"{i}. [{f.rule.severity.value}] {f.rule.name} — "
                f"{f.resource_kind}/{f.resource_name}"
                f"{f' (container: {f.container_name})' if f.container_name else ''}: "
                f"{f.details}"
            )
        return "\n".join(lines)
