from pathlib import Path


class Config():
    def __init__(self) -> None:
        self._results_dir = Path("results")
