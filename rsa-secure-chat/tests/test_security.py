"""Security tests. Run with:  python -m unittest discover -v   (or pytest)"""
import base64
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto_utils as cu
from app import app


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = {n: cu.generate_keypair() for n in ("bob", "eve")}

    def test_round_trip(self):
        enc = cu.encrypt_message(self.keys["bob"][1], "Hello Bob ✓")
        self.assertEqual(cu.decrypt_message(self.keys["bob"][0], **enc), "Hello Bob ✓")

    def test_long_message(self):
        msg = "A" * 50_000  # far larger than RSA-2048 could encrypt directly
        enc = cu.encrypt_message(self.keys["bob"][1], msg)
        self.assertEqual(cu.decrypt_message(self.keys["bob"][0], **enc), msg)

    def test_wrong_private_key_fails(self):
        enc = cu.encrypt_message(self.keys["bob"][1], "secret")
        with self.assertRaises(ValueError):
            cu.decrypt_message(self.keys["eve"][0], **enc)

    def test_tampered_ciphertext_fails(self):
        enc = cu.encrypt_message(self.keys["bob"][1], "secret")
        raw = bytearray(base64.b64decode(enc["ciphertext"]))
        raw[0] ^= 1
        enc["ciphertext"] = base64.b64encode(bytes(raw)).decode()
        with self.assertRaises(ValueError):
            cu.decrypt_message(self.keys["bob"][0], **enc)

    def test_same_message_gives_different_ciphertext(self):
        a = cu.encrypt_message(self.keys["bob"][1], "same")
        b = cu.encrypt_message(self.keys["bob"][1], "same")
        self.assertNotEqual(a["ciphertext"], b["ciphertext"])
        self.assertNotEqual(a["enc_key"], b["enc_key"])

    def test_garbage_key_rejected(self):
        enc = cu.encrypt_message(self.keys["bob"][1], "x")
        with self.assertRaises(ValueError):
            cu.decrypt_message("not a key", **enc)


class ApiTests(unittest.TestCase):
    def test_flow_and_access_control(self):
        tmp = tempfile.mkdtemp()
        app.config.update(DATABASE=os.path.join(tmp, "t.db"), TESTING=True)
        clients, priv = {}, {}
        for name in ("alice", "bob", "eve"):
            c = app.test_client()
            r = c.post("/api/register", json={"username": name, "password": "password123"})
            self.assertEqual(r.status_code, 201)
            priv[name] = r.get_json()["private_key"]
            c.post("/api/login", json={"username": name, "password": "password123"})
            clients[name] = c

        # unauthenticated access is rejected
        self.assertEqual(app.test_client().get("/api/inbox").status_code, 401)

        sent = clients["alice"].post("/api/send", json={"receiver": "bob", "message": "hi bob"})
        self.assertEqual(sent.status_code, 201)

        inbox = clients["bob"].get("/api/inbox").get_json()["messages"]
        mid = inbox[0]["id"]
        self.assertNotIn("hi bob", str(inbox))  # only ciphertext is exposed

        ok = clients["bob"].post("/api/decrypt", json={"message_id": mid, "private_key": priv["bob"]})
        self.assertEqual(ok.get_json()["message"], "hi bob")

        bad = clients["bob"].post("/api/decrypt", json={"message_id": mid, "private_key": priv["eve"]})
        self.assertEqual(bad.status_code, 400)  # wrong private key

        # Eve cannot request decryption of Bob's message at all
        eve = clients["eve"].post("/api/decrypt", json={"message_id": mid, "private_key": priv["eve"]})
        self.assertEqual(eve.status_code, 404)


if __name__ == "__main__":
    unittest.main()
