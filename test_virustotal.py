import unittest
from unittest.mock import Mock, patch

from app import check_virustotal


class TestVirusTotalIntegration(unittest.TestCase):

    @patch("app.requests.get")
    def test_successful_report(self, mock_get):
        response = Mock()
        response.status_code = 200
        response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 2,
                        "suspicious": 1,
                        "harmless": 60,
                        "undetected": 5,
                    },
                    "reputation": -3,
                }
            }
        }
        mock_get.return_value = response

        result = check_virustotal(
            "https://example.com",
            "test-api-key",
        )

        self.assertEqual(result["status"], "found")
        self.assertEqual(result["malicious"], 2)
        self.assertEqual(result["suspicious"], 1)
        self.assertEqual(result["harmless"], 60)
        self.assertEqual(result["undetected"], 5)
        self.assertEqual(result["reputation"], -3)

        mock_get.assert_called_once()
        self.assertEqual(
            mock_get.call_args.kwargs["headers"]["x-apikey"],
            "test-api-key",
        )

    @patch("app.requests.get")
    def test_report_not_found(self, mock_get):
        response = Mock()
        response.status_code = 404
        mock_get.return_value = response

        result = check_virustotal(
            "https://example.com",
            "test-api-key",
        )

        self.assertEqual(result["status"], "not_found")

    @patch("app.requests.get")
    def test_invalid_api_key(self, mock_get):
        response = Mock()
        response.status_code = 401
        mock_get.return_value = response

        result = check_virustotal(
            "https://example.com",
            "test-api-key",
        )

        self.assertEqual(result["status"], "error")
        self.assertIn("API key", result["message"])

    @patch("app.requests.get")
    def test_rate_limit(self, mock_get):
        response = Mock()
        response.status_code = 429
        mock_get.return_value = response

        result = check_virustotal(
            "https://example.com",
            "test-api-key",
        )

        self.assertEqual(result["status"], "rate_limited")

    @patch("app.requests.get")
    def test_network_timeout(self, mock_get):
        import requests

        mock_get.side_effect = requests.Timeout()

        result = check_virustotal(
            "https://example.com",
            "test-api-key",
        )

        self.assertEqual(result["status"], "error")
        self.assertIn("timed out", result["message"])


if __name__ == "__main__":
    unittest.main()
