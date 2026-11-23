"""Static safety contracts; never execute the installer or change host networking."""

import unittest
from pathlib import Path


INSTALLER = Path(__file__).resolve().parents[1] / "install.ps1"


class WindowsInstallerSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = INSTALLER.read_text(encoding="utf-8-sig")

    def section(self, start, end):
        self.assertIn(start, self.source)
        self.assertIn(end, self.source)
        return self.source.split(start, 1)[1].split(end, 1)[0]

    def test_new_config_is_persisted_as_isolated_without_overwriting_existing(self):
        config = self.section(
            "# ---------------------------------------------------------------- Egress configuration",
            "# ---------------------------------------------------------------- Stop existing workers",
        )
        self.assertIn('$WarpScope = "isolated"', config)
        self.assertIn('$EgressMode = "warp"', config)
        self.assertIn('if (Test-Path -LiteralPath $EgressCfg)', config)
        existing, new = config.split("} else {", 1)
        self.assertNotRegex(existing, r"WriteAllText|Set-Content|Out-File")
        self.assertIn('$WarpScope = [string]$ec.warp_scope', existing)
        self.assertIn('$EgressMode = [string]$ec.mode', existing)
        self.assertIn('warp_scope = $WarpScope', new)
        self.assertIn('mode = $EgressMode', new)
        self.assertIn('[IO.File]::WriteAllText(', new)
        self.assertIn('System.Text.UTF8Encoding($false)', new)

    def test_malformed_config_aborts_before_worker_or_firewall_changes(self):
        config = self.section(
            "# ---------------------------------------------------------------- Egress configuration",
            "# ---------------------------------------------------------------- Stop existing workers",
        )
        self.assertIn('$ec -isnot [pscustomobject]', config)
        self.assertRegex(config, r'\$ec\.warp_scope -cnotin @\("isolated", "tun"\)')
        self.assertRegex(config, r'\$ec\.mode -cnotin @\("warp", "tor", "custom", "clean"\)')
        self.assertRegex(config, r'(?s)catch\s*\{\s*Die "Invalid egress configuration')
        self.assertNotRegex(config, r'catch\s*\{\s*\}')

    def test_protocol_is_selected_for_proxy_before_setting_mode(self):
        setup = self.section(
            'Say "checking Cloudflare WARP configuration..."',
            'if (-not $SkipWarmCheck)',
        )
        self.assertIn('$DesiredOpMode = if ($WarpScope -eq "isolated" -or $EgressMode -in @("tor", "custom")) { "proxy" } else { "warp" }', setup)
        self.assertIn('$DesiredProtocol = if ($DesiredOpMode -eq "proxy") { "masque" } else { "wireguard" }', setup)
        protocol = setup.index('Invoke-Warp @("tunnel", "protocol", "set", $DesiredProtocol)')
        mode = setup.index('Invoke-Warp @("mode", $DesiredOpMode)')
        self.assertLess(protocol, mode)
        self.assertIn('Invoke-Warp @("proxy", "port", "40000")', setup)

    def test_unknown_mode_and_protocol_do_not_skip_configuration(self):
        self.assertRegex(self.source, r'if \(\$opMode -ne \$DesiredOpMode\)\s*\{')
        self.assertRegex(self.source, r'if \(\$protocol -ne \$DesiredProtocol\)\s*\{')
        self.assertNotIn('if ($opMode -and', self.source)
        self.assertNotIn('if ($protocol -and', self.source)

    def test_effective_settings_are_verified_before_connect_and_workers(self):
        verify = self.section(
            '# Verify effective settings',
            'Invoke-Warp @("connect")',
        )
        self.assertIn('Invoke-Warp @("-j", "settings")', verify)
        self.assertIn('ConvertFrom-Json -ErrorAction Stop', verify)
        self.assertIn('$settings.settings.warp_tunnel_protocol -ne $DesiredProtocol', verify)
        self.assertIn('$settings.settings.operation_mode -ne $DesiredOpMode', verify)
        self.assertRegex(verify, r'(?s)catch\s*\{\s*Die ')
        self.assertIn('refusing to connect or start workers', verify)
        self.assertLess(
            self.source.index('# Verify effective settings'),
            self.source.index('$tk1 = Register-BgTask'),
        )

    def test_failed_warp_commands_abort_instead_of_starting_workers(self):
        invoke = self.section('function Invoke-Warp(', 'Say "checking Cloudflare WARP configuration..."')
        self.assertRegex(invoke, r'(?s)if \(\$LASTEXITCODE -ne 0\)\s*\{\s*throw ')

    def test_skip_warm_check_only_gates_connection_wait(self):
        guard = self.source.index('if (-not $SkipWarmCheck)')
        self.assertEqual(self.source.count('if (-not $SkipWarmCheck)'), 1)
        for command in (
            '$EgressCfg =',
            'Invoke-Warp @("tunnel", "protocol", "set", $DesiredProtocol)',
            'Invoke-Warp @("mode", $DesiredOpMode)',
            '# Verify effective settings',
            'Invoke-Warp @("connect")',
        ):
            with self.subTest(command=command):
                self.assertIn(command, self.source)
                self.assertLess(self.source.index(command), guard)

    def test_upstream_credit_is_preserved(self):
        self.assertIn('Opencode Unlimited (Windows v4.0)', self.source)
        self.assertIn('Created & Maintained by Avatar (ShadowySphinX)', self.source)

    def test_isolated_install_does_not_install_tun_firewall_rules(self):
        firewall = self.section(
            '# ---------------------------------------------------------------- Optional Firewall Kill-Switch',
            '# ---------------------------------------------------------------- Connect WARP',
        )
        self.assertIn('if ($WarpScope -eq "tun" -and $EgressMode -in @("warp", "clean") -and (Test-IsAdmin))', firewall)


if __name__ == "__main__":
    unittest.main()
