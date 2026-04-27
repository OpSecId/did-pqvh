"""Small CLI for signing/verifying canonical JSON payloads."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .suite import make_proof, verify_payload


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_bytes(path: Path) -> bytes:
    return path.read_bytes()


def _add_serve_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    p.add_argument(
        "--no-reload",
        action="store_true",
        help="Disable autoreload (reload is on by default)",
    )


def _run_serve(*, host: str, port: int, reload: bool) -> None:
    import uvicorn

    uvicorn.run("did_pqvh.api:app", host=host, port=port, reload=reload)


def serve_main() -> None:
    """Console entrypoint for ``uv run serve`` (see ``[project.scripts]``)."""
    parser = argparse.ArgumentParser(prog="serve")
    _add_serve_args(parser)
    args = parser.parse_args()
    _run_serve(host=args.host, port=args.port, reload=not args.no_reload)


def main() -> None:
    parser = argparse.ArgumentParser(prog="did-pqvh")
    sub = parser.add_subparsers(dest="cmd", required=True)

    serve_cmd = sub.add_parser("serve", help="Run the HTTP API (FastAPI + uvicorn)")
    _add_serve_args(serve_cmd)

    sign_cmd = sub.add_parser("sign")
    sign_cmd.add_argument("--in", dest="payload", required=True, type=Path)
    sign_cmd.add_argument("--secret-key", required=True, type=Path)
    sign_cmd.add_argument("--verification-method", required=True)
    sign_cmd.add_argument("--out", required=True, type=Path)

    verify_cmd = sub.add_parser("verify")
    verify_cmd.add_argument("--in", dest="payload", required=True, type=Path)
    verify_cmd.add_argument("--proof", required=True, type=Path)
    verify_cmd.add_argument("--public-key", required=True, type=Path)

    args = parser.parse_args()

    if args.cmd == "serve":
        _run_serve(host=args.host, port=args.port, reload=not args.no_reload)
        return

    if args.cmd == "sign":
        payload = _read_json(args.payload)
        secret_key = _read_bytes(args.secret_key)
        proof = make_proof(
            payload,
            secret_key,
            verification_method=args.verification_method,
        )
        args.out.write_text(json.dumps(proof, indent=2), encoding="utf-8")
        return

    payload = _read_json(args.payload)
    proof = _read_json(args.proof)
    public_key = _read_bytes(args.public_key)
    ok = verify_payload(payload, proof, public_key)
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
