"""Alembic environment for Auth Service migrations"""
import os
import re
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# target_metadata not needed for running explicit migrations (only for autogenerate)
target_metadata = None


def get_url():
    url = os.environ.get("DATABASE_URL", "")
    # Strip ?sslmode=... — psycopg2 uses connect_args for SSL
    url = re.sub(r'[?&]sslmode=[^&]*', '', url).rstrip('?').rstrip('&')
    # Ensure sync driver (not asyncpg)
    url = url.replace("postgresql+asyncpg://", "postgresql://")
    return url


def run_migrations_offline():
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        version_table="alembic_version_auth",
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = get_url()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table="alembic_version_auth",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
