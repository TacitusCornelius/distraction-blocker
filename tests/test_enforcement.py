import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from distraction_blocker.enforcement import (
    FAN_DENY,
    FAN_OPEN_EXEC_PERM,
    FanotifyEnforcer,
    HostsEnforcer,
    _METADATA,
    _RESPONSE,
)


class HostsTests(unittest.TestCase):
    def test_preserves_bytes_and_repairs_section(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hosts"
            before = b"# keep\r\n127.0.0.1 local\r\n"
            path.write_bytes(before)
            enforcer = HostsEnforcer(path)
            enforcer.apply(["example.com", "v6.example"])
            managed = path.read_bytes()
            self.assertTrue(managed.startswith(before))
            self.assertEqual(enforcer.managed_hostnames(), {"example.com", "v6.example"})
            path.write_bytes(managed.replace(b"example.com", b"changed.example"))
            enforcer.apply(["example.com", "v6.example"])
            self.assertEqual(enforcer.managed_hostnames(), {"example.com", "v6.example"})
            enforcer.clear()
            self.assertEqual(path.read_bytes(), before)

    def test_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_bytes(b"x\n")
            link = Path(directory) / "hosts"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                HostsEnforcer(link).apply(["example.com"])


class FanotifyTests(unittest.TestCase):
    def test_overflow_marks_unhealthy(self):
        enforcer = FanotifyEnforcer(lambda: [])
        try:
            event = _METADATA.pack(_METADATA.size, 3, 0, _METADATA.size, 0x4000, -1, 0)
            enforcer.process_bytes(event)
            self.assertFalse(enforcer.healthy)
        finally:
            enforcer.close()

    def test_permission_event_resolves_exact_path(self):
        enforcer = FanotifyEnforcer(lambda: [])
        read_fd, write_fd = os.pipe()
        try:
            enforcer.set_blocked(["/usr/bin/example"])
            enforcer._fd = write_fd
            event = _METADATA.pack(_METADATA.size, 3, 0, _METADATA.size, FAN_OPEN_EXEC_PERM, read_fd, 0)
            with patch("os.readlink", return_value="/usr/bin/example"), patch("os.close") as close:
                enforcer.process_bytes(event)
                close.assert_called_once_with(read_fd)
                response = os.read(read_fd, _RESPONSE.size)
                self.assertEqual(_RESPONSE.unpack(response), (read_fd, FAN_DENY))
        finally:
            os.close(read_fd)
            os.close(write_fd)
            enforcer._fd = None
            enforcer.close()
