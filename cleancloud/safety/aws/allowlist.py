"""
Central definition of what AWS SDK operations CleanCloud is allowed to use.
This file is a SECURITY CONTRACT.
"""

ALLOWED_AWS_API_PREFIXES = (
    "Describe",
    "List",
    "Get",
)

FORBIDDEN_AWS_API_PREFIXES = (
    "Delete",
    "Put",
    "Update",
    "Create",
    "Attach",
    "Detach",
    "Modify",
    "Terminate",
    "Associate",
    "Disassociate",
)
