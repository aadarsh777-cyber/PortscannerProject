import unittest
from src.utils import expand_ports, expand_targets

class TestUtils(unittest.TestCase):
    def test_expand_ports_range(self):
        ports = expand_ports("20-22")
        self.assertEqual(ports, [20, 21, 22])

    def test_expand_ports_list(self):
        ports = expand_ports("22,80,443")
        self.assertEqual(ports, [22, 80, 443])

    def test_expand_targets_cidr(self):
        targets = expand_targets("127.0.0.0/30")
        # CIDR /30 gives usable hosts: .1 and .2
        self.assertIn("127.0.0.1", targets)
        self.assertIn("127.0.0.2", targets)

if __name__ == "__main__":
    unittest.main()