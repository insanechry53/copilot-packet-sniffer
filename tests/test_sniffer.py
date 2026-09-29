import unittest
import sys
import os

sys.path.insert(
    0,
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

from sniffer import mask_ip, redact_sensitive


class TestSniffer(unittest.TestCase):

    def test_mask_ip(self):
        self.assertEqual(
            mask_ip("192.168.1.25"),
            "192.168.1.xxx"
        )

    def test_redact_email(self):
        result = redact_sensitive("Email: test@example.com")
        self.assertEqual(
            result,
            "Email: [REDACTED_EMAIL]"
        )

    def test_redact_password_and_token(self):
        result = redact_sensitive(
            "password=FakePass123&token=FakeToken456"
        )
        self.assertEqual(
            result,
            "password=[REDACTED]&token=[REDACTED]"
        )

    def test_redact_authorization(self):
        result = redact_sensitive(
            "Authorization: Bearer FakeToken"
        )
        self.assertEqual(
            result,
            "Authorization: [REDACTED]"
        )


if __name__ == "__main__":
    unittest.main()
