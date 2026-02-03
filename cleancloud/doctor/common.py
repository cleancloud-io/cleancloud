class DoctorError(Exception):
    pass


def info(msg: str) -> None:
    print(msg)


def success(msg: str) -> None:
    print(f"[OK] {msg}")


def warn(msg: str) -> None:
    print(f"[!] {msg}")


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    raise DoctorError(msg)
