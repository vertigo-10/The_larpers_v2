"""Database engine and session management."""

from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings

_connect_args = {}
if settings.database_url.startswith("sqlite"):
    # FastAPI runs handlers across threads; SQLite needs this to allow it.
    _connect_args["check_same_thread"] = False

engine = create_engine(
    settings.database_url,
    connect_args=_connect_args,
    pool_pre_ping=True,
    echo=settings.debug,
)


if settings.database_url.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):
        cur = dbapi_conn.cursor()
        # WAL keeps the ingest writer from blocking dashboard readers.
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Additive schema changes applied to databases created by an earlier version.
# create_all() builds missing *tables* but never alters existing ones, so a
# column added to a model after someone has already run the app would be
# missing at runtime and every query touching it would fail.
#
# Deliberately an explicit list rather than a diff of the models: each entry is
# something a human decided is safe to apply unattended. Anything destructive —
# dropping a column, changing a type, backfilling — does not belong here and
# should be a real migration.
_ADDITIVE_COLUMNS = [
    ("users", "token_version", "INTEGER NOT NULL DEFAULT 0"),
    # Existing orgs predate the company/consumer distinction and were already
    # seeded with the enterprise-style demo topology (EDGE-01, DC-LB-01, ...),
    # so they default to "company" here rather than the model's "consumer"
    # default, which only applies to rows created after this column existed.
    ("orgs", "org_type", "VARCHAR(20) NOT NULL DEFAULT 'company'"),
    # Empty means "nobody can join this org by email domain", which is the only
    # safe default: turning on domain-based joining for every existing org
    # would silently widen the way into workspaces whose owners never asked
    # for it.
    ("orgs", "email_domain", "VARCHAR(255) NOT NULL DEFAULT ''"),
    # Everyone who already exists was let in before approval existed, so they
    # are active. Defaulting to 'pending' would lock every current user out of
    # their own account on the next deploy.
    ("users", "status", "VARCHAR(20) NOT NULL DEFAULT 'active'"),
    ("users", "join_method", "VARCHAR(20) NOT NULL DEFAULT 'founder'"),
    ("org_settings", "repeat_offender_window_minutes", "INTEGER NOT NULL DEFAULT 60"),
    # Nullable with no default, unlike every entry above. Incidents that predate
    # escalation were never tiered, and stamping them with one on deploy would
    # invent a decision nobody made — the alerts page would show bans no
    # operator ever chose.
    ("incidents", "mitigation_tier", "VARCHAR(20)"),
    ("incidents", "rate_limit_rps", "INTEGER"),
    ("incidents", "mitigation_expires_at", "TIMESTAMP"),
    # Empty means "this flow never told us its destination", which is the true
    # state of every row written before the column existed. The aggregate
    # detectors treat blank as unknown and skip it — if it defaulted to
    # something like '0.0.0.0' instead, every historical flow would appear to
    # share one target and the slow-DoS grouping would read the whole archive
    # as a single enormous attack on a host that does not exist.
    ("flows", "dst_ip", "VARCHAR(45) NOT NULL DEFAULT ''"),
    # Nullable and undefaulted on purpose. Every incident that already exists
    # was opened by the classifier, where the label is the whole finding, so
    # there is genuinely nothing to say — and backfilling a sentence would put
    # words in the record's mouth for incidents nobody has re-examined.
    ("incidents", "detail", "VARCHAR(200)"),
]


def _apply_additive_columns() -> None:
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    with engine.begin() as conn:
        for table, column, coltype in _ADDITIVE_COLUMNS:
            if table not in existing_tables:
                continue  # create_all() will have built it with the column
            columns = {c["name"] for c in inspector.get_columns(table)}
            if column in columns:
                continue
            # Every entry carries either NULL-ability or a DEFAULT, so this is
            # safe to run against a populated table.
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}"))


def init_db() -> None:
    from . import models  # noqa: F401  (register mappers before create_all)

    Base.metadata.create_all(bind=engine)
    _apply_additive_columns()
