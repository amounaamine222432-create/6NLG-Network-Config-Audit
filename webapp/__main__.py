"""Demarrage sur l'interface loopback uniquement (aucune exposition reseau)."""

import os

from waitress import serve

from .app import create_app


def main() -> None:
    port = int(os.environ.get("NETAUDIT_PORT", "5050"))
    if not 1 <= port <= 65535:
        raise ValueError("NETAUDIT_PORT doit etre compris entre 1 et 65535")
    print(f"NetAudit 6NLG disponible sur http://127.0.0.1:{port}")
    serve(create_app(), host="127.0.0.1", port=port, threads=4)


if __name__ == "__main__":
    main()
