import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import ouc_common
import proxy_chain
import tor_manager
import zen_proxy


class IsolatedProtocolTests(unittest.TestCase):
    def test_missing_windows_config_defaults_to_isolated(self):
        with mock.patch.object(proxy_chain.sys, "platform", "win32"), mock.patch.object(
            proxy_chain, "EGRESS_CONFIG_FILE"
        ) as config:
            config.is_file.return_value = False
            self.assertEqual(proxy_chain.get_egress_config()["warp_scope"], "isolated")

    def test_invalid_scope_does_not_select_full_system_mode(self):
        with mock.patch.object(proxy_chain, "EGRESS_CONFIG_FILE") as config:
            config.is_file.return_value = True
            config.read_text.return_value = '{"mode":"warp","warp_scope":"invalid"}'
            self.assertEqual(proxy_chain.get_egress_config()["warp_scope"], "isolated")

    def test_proxy_mode_disconnects_when_required_protocol_cannot_be_set(self):
        with mock.patch.object(ouc_common, "ensure_warp_protocol", return_value=False), mock.patch.object(
            ouc_common, "run_warp", return_value=(0, "Success")
        ) as run:
            with self.assertRaises(RuntimeError):
                ouc_common.ensure_warp_mode("warp-cli", "isolated")
        run.assert_called_once_with(["disconnect"], warp_bin="warp-cli", timeout=10.0)

    def test_strict_isolated_proxy_does_not_try_other_routes(self):
        with mock.patch.object(zen_proxy, "_active_warp_scope", return_value="isolated"), mock.patch.dict(
            "os.environ", {"OUC_STRICT_PROXY": "1"}
        ), mock.patch.object(tor_manager, "open_socks5_tunnel", side_effect=OSError("proxy down")), mock.patch.object(
            zen_proxy, "_open_pinned_any", return_value=(mock.sentinel.socket, "edge")
        ) as native:
            with self.assertRaises(ConnectionRefusedError):
                zen_proxy._open_warp_direct("opencode.ai", 443, mock.Mock())
        native.assert_not_called()

    def test_isolated_scope_overrides_wireguard_request(self):
        with mock.patch.object(ouc_common, "_current_warp_scope", return_value="isolated"), mock.patch.object(
            ouc_common, "get_warp_protocol", return_value="wireguard"
        ), mock.patch.object(ouc_common, "run_warp", return_value=(0, "Success")) as run:
            self.assertTrue(ouc_common.ensure_warp_protocol("wireguard", "warp-cli"))
        run.assert_called_once_with(
            ["tunnel", "protocol", "set", "MASQUE"], warp_bin="warp-cli", timeout=10.0
        )

    def test_tun_scope_preserves_wireguard_request(self):
        with mock.patch.object(ouc_common, "_current_warp_scope", return_value="tun"), mock.patch.object(
            ouc_common, "get_warp_protocol", return_value="wireguard"
        ), mock.patch.object(ouc_common, "run_warp") as run:
            self.assertTrue(ouc_common.ensure_warp_protocol("wireguard", "warp-cli"))
        run.assert_not_called()

    def test_proxy_mode_requires_compatible_protocol_first(self):
        with mock.patch.object(ouc_common, "ensure_warp_protocol", return_value=True) as protocol, mock.patch.object(
            ouc_common, "warp_mode", side_effect=["warp", "proxy"]
        ), mock.patch.object(ouc_common, "run_warp", return_value=(0, "Success")):
            ouc_common.ensure_warp_mode("warp-cli", "isolated")
        protocol.assert_called_once_with("masque", warp_bin="warp-cli")

    def test_proxy_mode_refuses_silent_full_tunnel_fallback(self):
        with mock.patch.object(ouc_common, "ensure_warp_protocol", return_value=True), mock.patch.object(
            ouc_common, "warp_mode", return_value="warp"
        ), mock.patch.object(ouc_common, "run_warp", return_value=(0, "Success")):
            with self.assertRaises(RuntimeError):
                ouc_common.ensure_warp_mode("warp-cli", "isolated")
