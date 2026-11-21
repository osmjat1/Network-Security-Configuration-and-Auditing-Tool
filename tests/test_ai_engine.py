"""Unit tests for the central NetSecureOps AI engine."""

import io
import json
import unittest
import urllib.error
from unittest.mock import patch

from src.ai_engine import AIEngineError, generate, generate_json


class FakeResponse:
    def __init__(self, data):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return json.dumps(self.data).encode("utf-8")


class TestAIGenerate(unittest.TestCase):

    @patch("src.ai_engine.urllib.request.urlopen")
    def test_successful_response(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse({
            "response": "AI analysis successful",
            "done_reason": "stop",
        })

        result = generate("Analyse this configuration")

        self.assertEqual(result, "AI analysis successful")
        mock_urlopen.assert_called_once()

    @patch("src.ai_engine.urllib.request.urlopen")
    def test_empty_response_is_rejected(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse({
            "response": "",
            "done_reason": "stop",
        })

        with self.assertRaises(AIEngineError):
            generate("Analyse this configuration")
    @patch("src.ai_engine.urllib.request.urlopen")
    def test_connection_failure(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        with self.assertRaises(AIEngineError):
            generate("Test connection")

    @patch("src.ai_engine.urllib.request.urlopen")
    def test_timeout_is_handled(self, mock_urlopen):
        mock_urlopen.side_effect = TimeoutError()

        with self.assertRaises(AIEngineError):
            generate("Test timeout")

    @patch("src.ai_engine.urllib.request.urlopen")
    def test_invalid_response_json_is_rejected(self, mock_urlopen):
        class InvalidResponse(FakeResponse):
            def read(self):
                return b"not valid json"

        mock_urlopen.return_value = InvalidResponse({})

        with self.assertRaises(AIEngineError):
            generate("Test invalid JSON")

    @patch("src.ai_engine.urllib.request.urlopen")
    def test_truncated_response_is_rejected(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse({
            "response": "Incomplete analysis",
            "done_reason": "length",
        })

        with self.assertRaises(AIEngineError):
            generate("Test truncation") 

class TestAIGenerateJSON(unittest.TestCase):

    @patch("src.ai_engine.generate")
    def test_valid_json_object(self, mock_generate):
        mock_generate.return_value = '{"risk": "high"}'

        result = generate_json("Return JSON")

        self.assertEqual(result, {"risk": "high"})

    @patch("src.ai_engine.generate")
    def test_invalid_json_is_rejected(self, mock_generate):
        mock_generate.return_value = "not json"

        with self.assertRaises(AIEngineError):
            generate_json("Return JSON")

    @patch("src.ai_engine.generate")
    def test_json_array_is_rejected(self, mock_generate):
        mock_generate.return_value = '["item1", "item2"]'

        with self.assertRaises(AIEngineError):
            generate_json("Return JSON")


if __name__ == "__main__":
    unittest.main()
