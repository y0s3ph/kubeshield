"""Security rules for KubeShield."""

from kubeshield.rules.base import Rule, registry
from kubeshield.rules.resources import *  # noqa: F401, F403
from kubeshield.rules.security import *  # noqa: F401, F403
from kubeshield.rules.reliability import *  # noqa: F401, F403
from kubeshield.rules.networking import *  # noqa: F401, F403

__all__ = ["Rule", "registry"]
