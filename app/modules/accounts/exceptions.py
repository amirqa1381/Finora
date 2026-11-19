"""Domain errors of the accounts module."""

from app.core.exceptions import AppError, AuthenticationError


class EmailAlreadyRegisteredError(AppError):
    status_code = 409
    code = "email_already_registered"
    default_message = "Email is already registered"


class InvalidCredentialsError(AuthenticationError):
    code = "invalid_credentials"
    default_message = "Email or password is wrong"


class InvalidRefreshTokenError(AuthenticationError):
    code = "invalid_refresh_token"
    default_message = "Invalid or expired refresh token"