"""MCP mediation (L1/L4) — pinning, poisoning, chain detection, transports."""

from .chain import EXFIL, RECON, STAGE, ChainDetector, classify
from .descriptors import ToolDescriptor, ToolPinner, scan_descriptor
from .mediator import McpMediator, ReviewResult, ToolReview
from .proxy import HttpUpstream, StdioUpstream, run_proxy
from .session import McpSession

__all__ = [
    "ChainDetector",
    "EXFIL",
    "HttpUpstream",
    "McpMediator",
    "McpSession",
    "RECON",
    "ReviewResult",
    "STAGE",
    "StdioUpstream",
    "ToolDescriptor",
    "ToolPinner",
    "ToolReview",
    "classify",
    "run_proxy",
    "scan_descriptor",
]
