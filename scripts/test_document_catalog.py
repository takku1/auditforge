#!/usr/bin/env python3
"""Tests for scripts/build_document_catalog.py."""

import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import build_document_catalog as bdc


class TestClassification(unittest.TestCase):
    def test_known_public_domain_sources(self):
        for source in ("Federal", "NIST", "State"):
            status, _ = bdc._classify(source)
            self.assertEqual(status, "public_domain")

    def test_known_copyrighted_sources(self):
        for source in ("ISO", "IEC"):
            status, note = bdc._classify(source)
            self.assertEqual(status, "copyrighted_registration_required")
            self.assertIsNotNone(note)

    def test_unknown_source_defaults_to_unknown(self):
        status, note = bdc._classify("Some Country Nobody Verified")
        self.assertEqual(status, "unknown")
        self.assertIsNone(note)


class TestBuild(unittest.TestCase):
    def test_manual_documents_always_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            with patch.object(bdc, "_rows_from_scf", return_value=[]), \
                 patch.object(bdc, "_rows_from_compliance_as_code", return_value=[]):
                counts = bdc.build(db_path)
            self.assertEqual(counts["manual"], len(bdc.MANUAL_DOCUMENTS))
            conn = sqlite3.connect(str(db_path))
            total = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
            self.assertEqual(total, len(bdc.MANUAL_DOCUMENTS))
            conn.close()

    def test_scf_rows_get_family_key_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            fake_row = {
                "fdi": "general-example-2020", "name": "Example Standard (2020)",
                "issuing_body": "Federal", "geography": "General",
                "source_url": "https://example.gov/standard.pdf",
                "family_key": "SCF_GENERAL_EXAMPLE_2020",
                "license_status": "public_domain", "license_note": "test",
            }
            with patch.object(bdc, "_rows_from_scf", return_value=[fake_row]), \
                 patch.object(bdc, "_rows_from_compliance_as_code", return_value=[]):
                bdc.build(db_path)
            conn = sqlite3.connect(str(db_path))
            row = conn.execute(
                "SELECT family_key, license_status FROM documents WHERE fdi = ?",
                ("general-example-2020",),
            ).fetchone()
            conn.close()
            self.assertEqual(row, ("SCF_GENERAL_EXAMPLE_2020", "public_domain"))

    def test_rebuild_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            with patch.object(bdc, "_rows_from_scf", return_value=[]), \
                 patch.object(bdc, "_rows_from_compliance_as_code", return_value=[]):
                bdc.build(db_path)
                bdc.build(db_path)
            conn = sqlite3.connect(str(db_path))
            total = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
            conn.close()
            self.assertEqual(total, len(bdc.MANUAL_DOCUMENTS))


class TestCacheDocument(unittest.TestCase):
    def _conn_with_row(self, fdi, license_status, url="https://example.gov/x.pdf"):
        conn = sqlite3.connect(":memory:")
        conn.executescript(bdc.SCHEMA)
        conn.execute(
            "INSERT INTO documents (fdi, name, source_url, catalog_source, license_status) "
            "VALUES (?, 'x', ?, 'manual', ?)",
            (fdi, url, license_status),
        )
        conn.commit()
        return conn

    @patch("requests.get")
    def test_refuses_copyrighted_without_network_call(self, mock_get):
        conn = self._conn_with_row("iec-doc", "copyrighted_registration_required")
        result = bdc.cache_document(conn, "iec-doc")
        self.assertIn("refused", result)
        mock_get.assert_not_called()

    @patch("requests.get")
    def test_refuses_unknown_without_network_call(self, mock_get):
        conn = self._conn_with_row("mystery-doc", "unknown")
        result = bdc.cache_document(conn, "mystery-doc")
        self.assertIn("refused", result)
        mock_get.assert_not_called()

    @patch("requests.get")
    def test_caches_public_domain_document(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.headers = {"Content-Type": "application/pdf"}
        mock_resp.content = b"%PDF-1.4 fake content"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        conn = self._conn_with_row("nist-doc", "public_domain")
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(bdc, "CACHE_DIR", Path(tmp)):
                result = bdc.cache_document(conn, "nist-doc")
                self.assertTrue(result.startswith("cached"))
                self.assertTrue((Path(tmp) / "nist-doc.pdf").exists())

        row = conn.execute(
            "SELECT full_text_cached, cached_path FROM documents WHERE fdi = ?",
            ("nist-doc",),
        ).fetchone()
        self.assertEqual(row[0], 1)
        self.assertIsNotNone(row[1])

    def test_unknown_fdi(self):
        conn = self._conn_with_row("real-doc", "public_domain")
        self.assertEqual(bdc.cache_document(conn, "does-not-exist"), "not-found")


if __name__ == "__main__":
    unittest.main(verbosity=2)
