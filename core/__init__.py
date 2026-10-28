# PortWatch core exports
from .gate import authorize_target, GateError, GATE_REJECTIONS

__all__ = ["authorize_target", "GateError", "GATE_REJECTIONS"]
