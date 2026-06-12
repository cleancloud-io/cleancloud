"""Shared AWS error classification helpers."""

from botocore.exceptions import ClientError

# Error codes that indicate a permission/authorization failure.
# Covers the common SageMaker, EC2, IAM, and service-specific variants.
_PERMISSION_ERROR_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "UnauthorizedException",
        "Client.UnauthorizedOperation",
    }
)


def is_permission_error(exc: ClientError) -> bool:
    """Return True when a ClientError represents an authorization failure."""
    code = exc.response.get("Error", {}).get("Code", "")
    return code in _PERMISSION_ERROR_CODES
