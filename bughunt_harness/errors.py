"""Harness exception types.

A small, typed hierarchy keeps CLI exit codes predictable and lets the
request broker distinguish policy refusals from network failures.
"""

from __future__ import annotations


class HarnessError(Exception):
    """Base class for all harness errors."""

    exit_code = 1


class ConfigError(HarnessError):
    """Invalid or missing harness configuration."""


class ProgramError(HarnessError):
    """Program registry / workspace problems."""


class ProgramNotFoundError(ProgramError):
    exit_code = 2

    def __init__(self, slug: str) -> None:
        super().__init__(f"program not found: {slug!r}")
        self.slug = slug


class ProgramNotActiveError(ProgramError):
    exit_code = 3

    def __init__(self, detail: str = "") -> None:
        super().__init__(detail or "no active program is bound in this session")


class ProgramInactiveError(ProgramError):
    """A live action was attempted against a program whose status is not active."""

    exit_code = 9

    def __init__(self, slug: str, status: str) -> None:
        super().__init__(f"program {slug!r} is {status!r}; live actions require status 'active'")
        self.slug = slug
        self.status = status


class EngagementValidationError(ProgramError):
    """Engagement configuration (program/scope/roe) is incomplete or invalid."""

    exit_code = 4


class ScopeError(HarnessError):
    """A target failed scope resolution or is out of scope."""


class PolicyError(HarnessError):
    """A proposed action was refused by the deterministic policy gate."""


class ApprovalRequiredError(PolicyError):
    """The action requires explicit human approval that is not yet granted."""

    exit_code = 5


class ActionForbiddenError(PolicyError):
    """The action is disabled/forbidden for this program."""

    exit_code = 6


class StateError(HarnessError):
    """Research-state / SQLite problems."""


class InvalidTransitionError(StateError):
    """A state-machine transition was attempted that is not permitted."""

    exit_code = 7


class SecretError(HarnessError):
    """Secret resolution failures (never include secret values)."""


class NetworkSafetyError(HarnessError):
    """A network action was attempted without the required authorization."""

    exit_code = 8