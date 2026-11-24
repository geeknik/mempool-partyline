"""Tests for CLI security warnings and main() wiring"""
import logging
from unittest.mock import MagicMock, patch

from partyline.cli import check_security_warnings, main


class TestCheckSecurityWarnings:
    """Test check_security_warnings function."""

    def test_localhost_no_warning(self, caplog):
        """No warning for localhost RPC."""
        config = MagicMock()
        config.get_primary_node.return_value.host = '127.0.0.1'
        config.get_primary_node.return_value.network.value = 'testnet'

        with caplog.at_level(logging.WARNING):
            result = check_security_warnings(config)

        assert result is True
        assert len(caplog.records) == 0

    def test_remote_rpc_warns(self, caplog):
        """Warning for remote RPC without encryption."""
        config = MagicMock()
        config.get_primary_node.return_value.host = '192.168.1.100'
        config.get_primary_node.return_value.network.value = 'testnet'

        with caplog.at_level(logging.WARNING):
            result = check_security_warnings(config)

        assert result is True
        assert len(caplog.records) >= 1
        assert "remote" in caplog.records[0].message.lower() or "insecure" in caplog.records[0].message.lower()

    def test_mainnet_warns(self, caplog):
        """Warning for mainnet usage."""
        config = MagicMock()
        config.get_primary_node.return_value.host = '127.0.0.1'
        config.get_primary_node.return_value.network.value = 'mainnet'

        with caplog.at_level(logging.WARNING):
            result = check_security_warnings(config)

        assert result is True
        assert len(caplog.records) >= 1
        assert "mainnet" in caplog.records[0].message.lower() or "real money" in caplog.records[0].message.lower()

    def test_multiple_warnings(self, caplog):
        """Both warnings shown for remote + mainnet."""
        config = MagicMock()
        config.get_primary_node.return_value.host = '10.0.0.50'
        config.get_primary_node.return_value.network.value = 'mainnet'

        with caplog.at_level(logging.WARNING):
            result = check_security_warnings(config)

        assert result is True
        assert len(caplog.records) >= 2


class TestMainWiring:
    """Test that main() calls security checks."""

    def test_main_calls_check_security_warnings(self):
        """Verify main() invokes check_security_warnings."""
        with (
            patch('partyline.cli.AppConfig') as mock_config,
            patch('partyline.cli.setup_logging'),
            patch('partyline.cli.ProcessHardening'),
            patch('partyline.cli.check_security_warnings') as mock_check,
        ):
            mock_config.load.return_value = MagicMock()
            mock_check.return_value = True
            with patch('partyline.cli.create_parser') as mock_parser:
                mock_parser.return_value.parse_args.return_value = MagicMock(
                    setup=False, tui=False, send=None, listen=False
                )
                try:
                    main([])
                except SystemExit:
                    pass
            mock_check.assert_called_once()

    def test_main_returns_zero_on_help(self):
        """main() returns 0 and prints help when no args."""
        with (
            patch('partyline.cli.AppConfig') as mock_config,
            patch('partyline.cli.setup_logging'),
            patch('partyline.cli.ProcessHardening'),
            patch('partyline.cli.check_security_warnings'),
        ):
            mock_config.load.return_value = MagicMock()
            with patch('partyline.cli.create_parser') as mock_parser:
                mock_parser.return_value.parse_args.return_value = MagicMock(
                    setup=False, tui=False, send=None, listen=False
                )
                result = main([])
                assert result == 0


class TestMainFlags:
    """Test CLI flag dispatch."""

    def test_setup_flag(self):
        """--setup calls run_setup."""
        with (
            patch('partyline.cli.AppConfig') as mock_config,
            patch('partyline.cli.setup_logging'),
            patch('partyline.cli.ProcessHardening'),
            patch('partyline.cli.check_security_warnings'),
            patch('partyline.cli.run_setup') as mock_run,
        ):
            mock_config.load.return_value = MagicMock()
            mock_run.return_value = 0
            with patch('partyline.cli.create_parser') as mock_parser:
                mock_parser.return_value.parse_args.return_value = MagicMock(
                    setup=True, tui=False, send=None, listen=False
                )
                result = main([])
                assert result == 0
            mock_run.assert_called_once()

    def test_tui_flag(self):
        """--tui calls run_tui."""
        with (
            patch('partyline.cli.AppConfig') as mock_config,
            patch('partyline.cli.setup_logging'),
            patch('partyline.cli.ProcessHardening'),
            patch('partyline.cli.check_security_warnings'),
            patch('partyline.cli.run_tui') as mock_run,
        ):
            mock_config.load.return_value = MagicMock()
            mock_run.return_value = 0
            with patch('partyline.cli.create_parser') as mock_parser:
                mock_parser.return_value.parse_args.return_value = MagicMock(
                    setup=False, tui=True, send=None, listen=False
                )
                result = main([])
                assert result == 0
            mock_run.assert_called_once()

    def test_send_flag(self):
        """--send calls send_message."""
        with (
            patch('partyline.cli.AppConfig') as mock_config,
            patch('partyline.cli.setup_logging'),
            patch('partyline.cli.ProcessHardening'),
            patch('partyline.cli.check_security_warnings'),
            patch('partyline.cli.send_message') as mock_send,
        ):
            mock_config.load.return_value = MagicMock()
            mock_send.return_value = 0
            with patch('partyline.cli.create_parser') as mock_parser:
                mock_parser.return_value.parse_args.return_value = MagicMock(
                    setup=False, tui=False, send="test message", listen=False
                )
                result = main([])
                assert result == 0
            mock_send.assert_called_once_with("test message")
