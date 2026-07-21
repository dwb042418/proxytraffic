"""Scenario action public API."""

from encrypted_traffic_platform.actions.base import ActionContext, ActionResult
from encrypted_traffic_platform.actions.builtin import execute_action

__all__ = ["ActionContext", "ActionResult", "execute_action"]
