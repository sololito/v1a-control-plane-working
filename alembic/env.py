"""Alembic env: autogenerate from app.models.

Baseline SQL lives in `migrations/00*.sql` (001..008, applied by
`deploy/install_server.sh` line by line; alembic is for what comes after).
"""
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context
from app.db import Base
import app.models  # noqa: F401  (register tables)
from app.config import get_settings

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)
target_metadata = Base.metadata


def run_migrations_offline():
    url = get_settings().database_url
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    cfg = config.get_section(config.config_ini_section) or {}
    cfg["sqlalchemy.url"] = get_settings().database_url
    engine = engine_from_config(cfg, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online() if not context.is_offline_mode() else run_migrations_offline()
