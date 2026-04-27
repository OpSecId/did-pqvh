"""Per-SCID Askar (SQLite) wallets: ``{DID_PQVH_WALLET_DIR}/{SCID}.sqlite``."""

from __future__ import annotations

import asyncio
import os
import pathlib
from typing import Any

from aries_askar import Store
from aries_askar.error import AskarError

# Askar entry names (single default profile per file).
_CAT = "did_pqvh"
_LOG = "scid_log"
_TOKEN = "access_token"


def wallet_dir() -> pathlib.Path | None:
    """Base directory for ``{{SCID}}.sqlite`` files; ``None`` disables Askar persistence."""
    raw = os.environ.get("DID_PQVH_WALLET_DIR", "").strip()
    if not raw:
        return None
    return pathlib.Path(raw).expanduser().resolve()


def askar_pass_key() -> str:
    """Raw store key; required when ``DID_PQVH_WALLET_DIR`` is set."""
    key = os.environ.get("DID_PQVH_ASKAR_PASS_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "DID_PQVH_ASKAR_PASS_KEY must be set when DID_PQVH_WALLET_DIR is set "
            "(generate once: `python -c \"from aries_askar import Store; print(Store.generate_raw_key())\"`)."
        )
    return key


def sqlite_uri_for_wallet_file(path: pathlib.Path) -> str:
    """Askar SQLite URI for an absolute path (``sqlite://`` + ``/abs/path``)."""
    p = path.resolve().as_posix()
    if not p.startswith("/"):
        return "sqlite:///" + p
    return "sqlite://" + p


def wallet_sqlite_path(bare_scid: str) -> pathlib.Path:
    """``{{wallet_dir}}/{{bare_scid}}.sqlite``."""
    base = wallet_dir()
    if base is None:
        raise RuntimeError("wallet_dir() is None")
    if not bare_scid or any(c in bare_scid for c in ("/", "\\", "\0")):
        raise ValueError(f"Unsafe SCID for wallet filename: {bare_scid!r}")
    return base / f"{bare_scid}.sqlite"


def _run(coro):
    """Run async Askar code from sync FastAPI handlers (uvicorn worker thread)."""
    return asyncio.run(coro)


async def _open_store(uri: str, *, provision: bool) -> Store:
    key = askar_pass_key()
    method = "raw"
    if provision:
        return await Store.provision(uri, method, key, recreate=False)
    return await Store.open(uri, method, key)


async def wallet_read(bare_scid: str) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Return ``(log_rows_or_none_if_no_file, access_token_or_none)``."""
    path = wallet_sqlite_path(bare_scid)
    if not path.is_file():
        return None, None
    uri = sqlite_uri_for_wallet_file(path)
    store = await _open_store(uri, provision=False)
    try:
        async with store as session:
            le = await session.fetch(_CAT, _LOG)
            te = await session.fetch(_CAT, _TOKEN)
            rows = le.value_json if le else None
            tok = te.value.decode("utf-8") if te and te.value else None
            if rows is not None and not isinstance(rows, list):
                rows = None
            return rows, tok
    finally:
        await store.close()


async def wallet_write_full(
    bare_scid: str,
    rows: list[dict[str, Any]],
    access_token: str | None,
    *,
    provision: bool,
) -> None:
    base = wallet_dir()
    assert base is not None
    base.mkdir(parents=True, exist_ok=True)
    path = wallet_sqlite_path(bare_scid)
    uri = sqlite_uri_for_wallet_file(path)
    store = await _open_store(uri, provision=provision)
    try:
        async with store.transaction() as txn:
            if await txn.fetch(_CAT, _LOG):
                await txn.replace(_CAT, _LOG, value_json=rows)
            else:
                await txn.insert(_CAT, _LOG, value_json=rows)
            if access_token is None:
                try:
                    await txn.remove(_CAT, _TOKEN)
                except AskarError:
                    pass
            else:
                if await txn.fetch(_CAT, _TOKEN):
                    await txn.replace(_CAT, _TOKEN, value=access_token.encode("utf-8"))
                else:
                    await txn.insert(_CAT, _TOKEN, value=access_token.encode("utf-8"))
            await txn.commit()
    finally:
        await store.close()


async def wallet_remove_file(bare_scid: str) -> None:
    path = wallet_sqlite_path(bare_scid)
    if not path.is_file():
        return
    uri = sqlite_uri_for_wallet_file(path)
    await Store.remove(uri)


def read_wallet_sync(bare_scid: str) -> tuple[list[dict[str, Any]] | None, str | None]:
    return _run(wallet_read(bare_scid))


def write_wallet_sync(
    bare_scid: str,
    rows: list[dict[str, Any]],
    access_token: str | None,
    *,
    provision: bool,
) -> None:
    _run(wallet_write_full(bare_scid, rows, access_token, provision=provision))


def remove_wallet_sync(bare_scid: str) -> None:
    _run(wallet_remove_file(bare_scid))
