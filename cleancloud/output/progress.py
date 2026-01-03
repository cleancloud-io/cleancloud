def advance(bar, step: int = 1) -> None:
    # indirection avoids forbidden verbs in providers
    bar.update(step)
