"""Import every module models file here so Alembic sees all tables."""

from app.modules.accounts import models as _accounts_models  # noqa: F401
from app.modules.audit import models as _audit_models  # noqa: F401
