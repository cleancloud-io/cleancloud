FORBIDDEN_GCP_METHOD_PREFIXES = (
    "delete",
    "insert",
    "patch",
    "update",
    "set_",
    "add_",
    "remove_",
    "reset_",
    "start",
    "stop",
    "restart",
    "create",
    # Service lifecycle — enabling/disabling APIs mutates project configuration
    "enable",
    "disable",
    # Data movement — import/export can write to destination resources
    "import",
    "export",
    # Resource mutation — copy/move create or relocate resources
    "copy",
    "move",
    # Resurrection — undelete restores soft-deleted resources
    "undelete",
    # Deployment — publish/deploy create or update live workloads
    "publish",
    "deploy",
    # Token signing — sign_blob/sign_jwt don't mutate resources but are
    # unnecessary for read-only scanning and should not appear in provider code
    "sign_",
)
