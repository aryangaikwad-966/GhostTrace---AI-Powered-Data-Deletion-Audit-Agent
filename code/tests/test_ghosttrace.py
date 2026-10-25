import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main


class AuthorizationTests(unittest.TestCase):
    def test_english_deletion(self):
        self.assertTrue(main.is_deletion_authorized("Please permanently delete my account."))

    def test_french_deletion(self):
        self.assertTrue(main.is_deletion_authorized("Je demande la suppression définitive de mon compte."))

    def test_japanese_deletion(self):
        self.assertTrue(main.is_deletion_authorized("アカウントを削除してください。"))

    def test_access_request_is_not_deletion(self):
        self.assertFalse(main.is_deletion_authorized("Please send me a copy of my data."))

    def test_explicit_negation_is_not_deletion(self):
        self.assertFalse(main.is_deletion_authorized("Do not delete my account; I only want to change my email."))

    def test_historical_identity_is_cut_off(self):
        row = {"user_id": "user_1", "email": "new@example.test", "updated_at": "2026-10-02T00:00:00Z"}
        history = {"user_1": {("email", "old@example.test", "2025-01-01T00:00:00Z"), ("email", "new@example.test", "2026-10-02T00:00:00Z")}}
        uid, _emails, _ids = main.resolve_identities("old@example.test", {}, {"user_1": row}, history, "2026-09-01T00:00:00Z")
        self.assertEqual(uid, "user_1")
        uid, _emails, _ids = main.resolve_identities("new@example.test", {"new@example.test": row}, {"user_1": row}, history, "2026-09-01T00:00:00Z")
        self.assertIsNone(uid)


if __name__ == "__main__":
    unittest.main()
