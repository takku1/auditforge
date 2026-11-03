"""Calibration farm (intentionally vulnerable, small). Ground truth in
benchmark/ground-truth/farm.json. Tuning is allowed against this target
only - never against held-out sets."""

import sqlite3
import subprocess


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = '%s'" % user_id)
    return cur.fetchone()


def search_users(conn, term):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name LIKE '%" + term + "%'")
    return cur.fetchall()
