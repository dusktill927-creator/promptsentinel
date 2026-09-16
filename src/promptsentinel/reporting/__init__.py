"""Report formats for consumers other than a human at a terminal."""

from promptsentinel.reporting.html import render_report
from promptsentinel.reporting.sarif import to_sarif

__all__ = ["render_report", "to_sarif"]
