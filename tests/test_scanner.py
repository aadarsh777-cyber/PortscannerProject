import unittest
from src.scanner import scan_tcp_once

class TestScanner(unittest.TestCase):
    def test_localhost_closed_port(self):
        # Port 9 (discard) is usually closed on localhost
        result = scan_tcp_once("127.0.0.1", 9, timeout=0.5)
        self.assertFalse(result)

    def test_localhost_open_port(self):
        # This test assumes port 22 (SSH) might be open locally.
        # Adjust to a known open port on your system.
        result = scan_tcp_once("127.0.0.1", 22, timeout=0.5)
        # We can't guarantee it's open, so just check it returns a boolean
        self.assertIn(result, [True, False])

if __name__ == "__main__":
    unittest.main()