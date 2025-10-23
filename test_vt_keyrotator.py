#!/usr/bin/env python3
"""
Basic tests for VT-KeyRotator utility
"""

import unittest
import json
import os
import tempfile
from unittest.mock import patch, Mock
from vt_keyrotator import VTKeyRotator, load_config


class TestVTKeyRotator(unittest.TestCase):
    """Test cases for VTKeyRotator class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.api_keys = ["test_key_1", "test_key_2", "test_key_3"]
        self.scanner = VTKeyRotator(self.api_keys)
    
    def test_initialization(self):
        """Test that VTKeyRotator initializes correctly."""
        self.assertEqual(len(self.scanner.api_keys), 3)
        self.assertEqual(self.scanner.current_key_index, 0)
        self.assertEqual(self.scanner.retry_attempts, 3)
        self.assertEqual(self.scanner.retry_delay, 2)
        self.assertEqual(self.scanner.request_timeout, 10)
    
    def test_initialization_no_keys(self):
        """Test that initialization fails without API keys."""
        with self.assertRaises(ValueError):
            VTKeyRotator([])
    
    def test_get_current_key(self):
        """Test getting the current API key."""
        self.assertEqual(self.scanner._get_current_key(), "test_key_1")
    
    def test_rotate_key(self):
        """Test key rotation."""
        self.assertEqual(self.scanner.current_key_index, 0)
        self.scanner._rotate_key()
        self.assertEqual(self.scanner.current_key_index, 1)
        self.scanner._rotate_key()
        self.assertEqual(self.scanner.current_key_index, 2)
        # Should wrap around
        self.scanner._rotate_key()
        self.assertEqual(self.scanner.current_key_index, 0)
    
    @patch('vt_keyrotator.requests.get')
    def test_successful_scan(self, mock_get):
        """Test successful IP scan."""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2,
                        "undetected": 83,
                        "harmless": 0,
                        "timeout": 0
                    }
                }
            }
        }
        mock_get.return_value = mock_response
        
        result = self.scanner.scan_ip("8.8.8.8")
        self.assertIsNotNone(result)
        malicious, total = result
        self.assertEqual(malicious, 5)
        self.assertEqual(total, 90)
    
    @patch('vt_keyrotator.requests.get')
    def test_rate_limit_handling(self, mock_get):
        """Test rate limit handling with key rotation."""
        # First call returns rate limit
        mock_response_429 = Mock()
        mock_response_429.status_code = 429
        
        # Second call succeeds
        mock_response_200 = Mock()
        mock_response_200.status_code = 200
        mock_response_200.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 90,
                        "harmless": 0,
                        "timeout": 0
                    }
                }
            }
        }
        
        mock_get.side_effect = [mock_response_429, mock_response_200]
        
        result = self.scanner.scan_ip("8.8.8.8")
        self.assertIsNotNone(result)
        malicious, total = result
        self.assertEqual(malicious, 0)
        self.assertEqual(total, 90)
        # Verify key was rotated
        self.assertEqual(self.scanner.current_key_index, 1)
    
    def test_load_config(self):
        """Test configuration loading."""
        # Create a temporary config file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config = {
                "api_keys": ["key1", "key2"],
                "retry_attempts": 5,
                "retry_delay": 3,
                "request_timeout": 15
            }
            json.dump(config, f)
            config_file = f.name
        
        try:
            loaded_config = load_config(config_file)
            self.assertEqual(loaded_config["api_keys"], ["key1", "key2"])
            self.assertEqual(loaded_config["retry_attempts"], 5)
            self.assertEqual(loaded_config["retry_delay"], 3)
            self.assertEqual(loaded_config["request_timeout"], 15)
        finally:
            os.unlink(config_file)


if __name__ == '__main__':
    unittest.main()
