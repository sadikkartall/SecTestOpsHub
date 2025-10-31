from logging.config import fileConfig
import os
from sqlalchemy import engine_from_config, pool
from alembic import context

# Alembic Config
config = context.config

# Logging
if config.config_file_name is not None:
	fileConfig(config.config_file_name)

# Database URL from env
DATABASE_URL = os.getenv(
	"DATABASE_URL",
	"postgresql://sectestops:securepassword123@postgres:5432/sectestops_db"
)
config.set_main_option("sqlalchemy.url", DATABASE_URL)

# Target metadata (SQLAlchemy Base)
from models import Base  # noqa

target_metadata = Base.metadata


def run_migrations_offline():
	url = config.get_main_option("sqlalchemy.url")
	context.configure(
		url=url,
		target_metadata=target_metadata,
		literal_binds=True,
		dialect_opts={"paramstyle": "named"},
		include_schemas=True,
	)

	with context.begin_transaction():
		context.run_migrations()


def run_migrations_online():
	connectable = engine_from_config(
		config.get_section(config.config_ini_section),
		prefix="sqlalchemy.",
		poolclass=pool.NullPool,
	)

	with connectable.connect() as connection:
		context.configure(
			connection=connection,
			target_metadata=target_metadata,
			compare_type=True,
			include_schemas=True,
		)

		with context.begin_transaction():
			context.run_migrations()


if context.is_offline_mode():
	run_migrations_offline()
else:
	run_migrations_online()
