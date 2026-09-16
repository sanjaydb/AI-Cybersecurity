"""Intentionally insecure teaching sample. Do not copy into production."""

import os
import sqlite3

# CWE-798: hardcoded secret for the scanner to find
API_KEY = "sk_live_example_do_not_use_1234567890"
DB_PASSWORD = "P@ssw0rd!"


def search_user(name: str) -> list:
    conn = sqlite3.connect(":memory:")
    # CWE-89: string-built SQL
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return conn.execute(query).fetchall()


def ping_host(host: str) -> int:
    # CWE-78: command built from a string
    return os.system("ping -c 1 " + host)


def insecure_request():
    import ssl
    # CWE-295: TLS verify disabled (pattern only)
    return ssl._create_unverified_context()


if __name__ == "__main__":
    app_debug = True  # CWE-489
    print("demo only", app_debug)
