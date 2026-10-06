"""Additive schema guard for already-initialized dev databases.

`Base.metadata.create_all` creates missing *tables* but never adds missing
*columns* to tables that already exist, so a dev SQLite file created before a
new model field lands would start failing on SELECT. Production Postgres runs
the numbered SQL in `migrations/` instead; this guard only exists so a local
`python run_server.py` keeps working across upgrades.

Columns are always added as nullable, so the statement cannot fail on a
populated table. Any failure is logged and swallowed: this is a convenience,
not the migration path.
"""
import logging

from sqlalchemy import inspect, text

log = logging.getLogger(__name__)


def _compile_type(col, engine) -> str:
    if type(col.type).__name__ == "GUID":
        return "UUID" if engine.dialect.name == "postgresql" else "VARCHAR(36)"
    return col.type.compile(engine.dialect)


def ensure_additive_schema(engine) -> list[str]:
    """Bring `engine`'s schema up to the models. Returns applied statements."""
    applied: list[str] = []
    insp = inspect(engine)
    existing = set(insp.get_table_names())
    from app.db import Base
    import app.models  # noqa: F401  (register metadata)

    for table in Base.metadata.sorted_tables:
        if table.name not in existing:
            continue  # create_all() created it before we got here
        have = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in have:
                continue
            stmt = f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {_compile_type(col, engine)}'
            try:
                with engine.begin() as conn:
                    conn.execute(text(stmt))
                applied.append(stmt)
                log.info("schema_guard: %s", stmt)
            except Exception as exc:  # pragma: no cover - dialect specific
                log.warning("schema_guard failed (%s): %s", stmt, exc)
    return applied
