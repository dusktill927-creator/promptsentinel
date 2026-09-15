"""Target adapters: the systems under test."""

from promptsentinel.targets.base import (
    ChatMessage,
    Target,
    TargetCapability,
    TargetResponse,
    ToolCall,
    ToolSpec,
)
from promptsentinel.targets.factory import build_target

__all__ = [
    "ChatMessage",
    "Target",
    "TargetCapability",
    "TargetResponse",
    "ToolCall",
    "ToolSpec",
    "build_target",
]
