
import unittest
from app import analyze_url


class TestPhishingDetector(unittest.TestCase):

    # Original scoring tests
    def test_https_example(self):
        self.assertEqual(analyze_url("https://example.com")[0], 0)

    def test_http_warning(self):
        self.assertEqual(analyze_url("http://example.com")[0], 15)

    def test_suspicious_login_subdomain(self):
        self.assertEqual(
            analyze_url("http://paypal-login.example.com")[0], 25
        )

    def test_ip_address_and_login(self):
        self.assertEqual(
            analyze_url("https://192.0.2.1/login")[0], 30
        )

    # Input validation tests
    def test_empty_url(self):
        score, findings, _ = analyze_url("")
        self.assertIsNone(score)
        self.assertTrue(findings)

    def test_whitespace_in_url(self):
        self.assertIsNone(analyze_url("https://example .com")[0])

    def test_unsupported_scheme(self):
        self.assertIsNone(analyze_url("ftp://example.com")[0])

    def test_javascript_scheme(self):
        self.assertIsNone(analyze_url("javascript:alert(1)")[0])

    # Hostname and port edge cases
    def test_empty_domain_label(self):
        self.assertIsNone(analyze_url("https://example..com")[0])

    def test_hostname_label_starts_with_hyphen(self):
        self.assertIsNone(analyze_url("https://-bad.com")[0])

    def test_port_out_of_range(self):
        self.assertIsNone(analyze_url("https://example.com:99999")[0])

    def test_empty_port(self):
        self.assertIsNone(analyze_url("https://example.com:")[0])

    def test_invalid_ipv4(self):
        self.assertIsNone(analyze_url("https://999.999.999.999")[0])

    # Valid URL variations
    def test_domain_without_scheme(self):
        self.assertEqual(analyze_url("example.com")[0], 0)

    def test_valid_port(self):
        self.assertEqual(analyze_url("https://example.com:8080")[0], 0)


if __name__ == "__main__":
    unittest.main()
