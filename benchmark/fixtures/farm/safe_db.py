"""Calibration farm: safe counterparts (must NOT flag)."""

import hmac
import os
import sqlite3

DB_PASSWORD = os.environ.get("FARM_DB_PASSWORD", "")


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def tokens_equal(a, b):
    return hmac.compare_digest(a, b)
