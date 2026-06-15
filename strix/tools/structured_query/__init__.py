# Line-accurate YAML/JSON path resolution tools.
#
# The inverse of code_graph_get_symbol_at: map a structural path to its
# value + line range so the agent can cite a real file:line for findings
# in workflow / IaC / config files, instead of the synthetic SECURITY.md
# anchor. Closes the structured-file slice of the location-quality gap
# (project_strix_location_quality_audit_20260615). PyYAML + stdlib only.

from .structured_query_actions import structured_find, structured_query


__all__ = [
    "structured_find",
    "structured_query",
]
