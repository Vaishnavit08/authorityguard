class DomainError(Exception):
    """A rule violation detected in backend code. Rendered as {"detail": {"code", "message"}}."""

    def __init__(self, code: str, message: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def not_found(code: str, what: str) -> DomainError:
    return DomainError(code, f"{what} does not exist.", 404)
