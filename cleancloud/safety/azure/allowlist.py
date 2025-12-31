"""
Central definition of allowed vs forbidden Azure SDK calls.
"""

ALLOWED_AZURE_METHOD_PREFIXES = (
    "list",
    "get",
)

FORBIDDEN_AZURE_METHOD_PREFIXES = (
    "delete",
    "begin_delete",
    "create",
    "begin_create",
    "update",
    "begin_update",
)
