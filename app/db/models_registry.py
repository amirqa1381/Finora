"""Import every module models file here so Alembic sees all tables."""

from app.modules.accounts import models as _accounts_models  # noqa: F401
from app.modules.users import models as _users_models  # noqa: F401