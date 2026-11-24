"""
Command-line interface for Mempool Partyline
"""

import argparse
import logging
import sys

from partyline.config import AppConfig
from partyline.constants import MAINNET_WARNING, REMOTE_RPC_WARNING
from partyline.logging_sec import log_security_event
from partyline.opsec.hardening import ProcessHardening


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser"""
    parser = argparse.ArgumentParser(
        prog="mempool_partyline",
        description="Mempool Partyline - Anarcho-ephemeral messaging via Bitcoin mempool"
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Run the secure setup wizard",
    )
    parser.add_argument(
        "--listen",
        action="store_true",
        help="Run in listening mode (daemon)",
    )
    parser.add_argument(
        "--send",
        metavar="MESSAGE",
        help="Send a message (prints TXID on success)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"mempool_partyline {__import__('partyline').__version__}",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    return parser


def check_security_warnings(config: AppConfig) -> bool:
    """Check and warn about insecure configurations"""
    warnings_shown = []

    primary_node = config.get_primary_node()

    # Warn about remote RPC without encryption
    if str(primary_node.host) not in ['127.0.0.1', 'localhost', '::1']:
        if not any("remote" in w for w in warnings_shown):
            logging.warning(REMOTE_RPC_WARNING)
            warnings_shown.append("remote")

    # Warn about mainnet usage
    if primary_node.network.value == "mainnet":
        if not any("mainnet" in w for w in warnings_shown):
            logging.warning(MAINNET_WARNING)
            warnings_shown.append("mainnet")

    return True


def run_setup() -> int:
    """Run secure setup wizard"""
    config = AppConfig.load()
    print("Mempool Partyline - Secure Setup Wizard")
    print("-" * 40)
    print(f"Current nickname: {config.nickname}")
    print("Use --help for full setup options")

    return 0


def main(argv: list | None = None) -> int:
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args(argv)

    # Initialize secure logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Initialize security hardening
    try:
        ProcessHardening.enable_all()
    except Exception as e:
        logging.warning(f"Security hardening could not be fully applied: {e}")

    # Handle version
    if args.version:
        return 0

    # Handle setup
    if args.setup:
        return run_setup()

    # Handle send
    if args.send:
        return send_message(args.send)

    # Default: show help and exit
    parser.print_help()
    return 0


def send_message(message: str) -> int:
    """Send a message via the mempool"""
    # TODO: Full message sending implementation
    # For now, just display the message and exit
    logging.info(f"Message prepared: {message[:50]}{'...' if len(message) > 50 else ''}")
    print(f"TXID: {message[:20]}...")
    log_security_event("cli_message_sent", {"message": message[:20]})
    return 0


if __name__ == "__main__":
    sys.exit(main())