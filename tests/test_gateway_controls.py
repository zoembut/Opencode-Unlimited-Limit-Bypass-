import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import avatar_ui


class GatewayControlTests(unittest.TestCase):
    def setUp(self):
        self.api = avatar_ui.AvatarControlApi.__new__(avatar_ui.AvatarControlApi)
        self.gateway = mock.Mock()
        self.gateway.get_gateway_state.return_value = {"running": False, "api_key_set": True}

    def test_state_does_not_reveal_key(self):
        with mock.patch.dict(sys.modules, {"api_gateway": self.gateway}):
            state = self.api.get_api_gateway()
        self.assertNotIn("key", state)
        self.gateway.get_gateway_key.assert_not_called()

    def test_save_preserves_key_when_omitted(self):
        with mock.patch.dict(sys.modules, {"api_gateway": self.gateway}):
            result = self.api.save_api_gateway("https://provider.example/v1", None, 41988, True)
        self.assertTrue(result["ok"])
        self.gateway.configure_gateway.assert_called_once_with(
            upstream_url="https://provider.example/v1", upstream_key=None, port=41988, via_warp=True
        )

    def test_failure_never_echoes_credentials(self):
        self.gateway.start_gateway.side_effect = RuntimeError("sensitive upstream key")
        with mock.patch.dict(sys.modules, {"api_gateway": self.gateway}):
            result = self.api.start_api_gateway()
        self.assertFalse(result["ok"])
        self.assertNotIn("sensitive", str(result))

    def test_key_is_revealed_only_explicitly(self):
        self.gateway.get_gateway_key.return_value = "test-local-key"
        with mock.patch.dict(sys.modules, {"api_gateway": self.gateway}):
            result = self.api.reveal_api_gateway_key()
        self.assertEqual(result, {"ok": True, "key": "test-local-key"})
