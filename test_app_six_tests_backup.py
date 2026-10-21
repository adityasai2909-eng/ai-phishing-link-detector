import unittest

from app import analyze_url


class TestPhishingDetector(unittest.TestCase):

    def test_safe_example_structure(self):
        score, findings, _ = analyze_url("https://example.com")
        self.assertEqual(score, 0)

    def test_http_warning(self):
        score, findings, _ = analyze_url("http://example.com")
        self.assertEqual(score, 15)

    def test_suspicious_login_subdomain(self):
        score, findings, _ = analyze_url(
            "http://paypal-login.example.com"
        )
        self.assertEqual(score, 25)

    def test_ip_address_and_login(self):
        score, findings, _ = analyze_url(
            "https://192.0.2.1/login"
        )
        self.assertEqual(score, 30)

    def test_empty_url(self):
        score, findings, _ = analyze_url("")
        self.assertIsNone(score)
        self.assertTrue(findings)

    def test_invalid_scheme(self):
        score, findings, _ = analyze_url("ftp://example.com")
        self.assertIsNone(score)
        self.assertTrue(findings)


if __name__ == "__main__":
    unittest.main()