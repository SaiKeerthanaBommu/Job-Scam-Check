"""Scam checker for students and new grads (job and interview-invitation scams)."""
from .core import Finding, split_lines, verify
from .pipeline import analyze, Report

__all__ = ["Finding", "split_lines", "verify", "analyze", "Report"]
