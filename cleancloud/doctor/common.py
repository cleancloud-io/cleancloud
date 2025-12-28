class DoctorError(Exception):
    pass


def info(msg: str) -> None:
    print(msg)


def success(msg: str) -> None:
    print(f"✔ {msg}")


def warn(msg: str) -> None:
    print(f"⚠ {msg}")


def fail(msg: str) -> None:
    print(f"❌ {msg}")
    raise DoctorError(msg)
