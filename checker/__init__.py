"""Code compliance checker: static analysis + scoring + a pass/fail quality gate."""
from .engine import analyze, load_policy
from .rules import RULES

__all__ = ["analyze", "load_policy", "RULES"]
