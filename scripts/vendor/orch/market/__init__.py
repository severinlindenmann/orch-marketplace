"""Not a vendored file: the one name the vendored ``orch.addons.lockfile`` and ``envtree`` import from core's
``orch.market``. Same shape as core's ``MarketError`` (``code``, ``reason``); nothing else of core's package is here."""


class MarketError(Exception):
    def __init__(self, code: str, reason: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.reason = reason
