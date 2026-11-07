"""Base application errors and the mapping to HTTP responses."""


class AppError(Exception):
    status_code = 400
    code = "app_error"
