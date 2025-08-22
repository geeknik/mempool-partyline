#!/usr/bin/env python3
# mempool_partyline.py
# Anarcho-ephemeral Mempool Messaging System with TUI

import os
import time
import base64
import json
import zmq
import logging
import curses
import threading
import argparse
import getpass
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from bitcoinrpc.authproxy import AuthServiceProxy

# --- Message Class ---
@dataclass
class Message:
    content: str
    timestamp: float
    sender: str = "Unknown"
    txid: Optional[str] = None
    
    def formatted(self) -> str:
        time_str = datetime.fromtimestamp(self.timestamp).strftime('%H:%M:%S')
        return f"[{time_str}] {self.sender}: {self.content}"


# --- Configuration Management ---
class Config:
    def __init__(self, config_file: Optional[str] = None):
        self.config_path = config_file or os.path.expanduser("~/.config/mempool_partyline/config.json")
        self.defaults = {
            'rpc_user': "yourrpcuser",
            'rpc_password': "yourrpcpass",
            'rpc_port': "18443",
            'rpc_host': "127.0.0.1",
            'zmq_tx_endpoint': "tcp://127.0.0.1:28332",
            'nickname': "anonymous",
            'log_file': os.path.expanduser("~/.config/mempool_partyline/partyline.log"),
            'poll_interval': 30
        }
        self.config = self.load_config()
        
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default if not exists"""
        config_dir = os.path.dirname(self.config_path)
        if not os.path.exists(config_dir):
            os.makedirs(config_dir, exist_ok=True)
            
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logging.error(f"Error loading config: {e}")
                return self.defaults
        else:
            self.save_config(self.defaults)
            return self.defaults
    
    def save_config(self, config: Dict[str, Any]) -> None:
        """Save configuration to file"""
        try:
            config_dir = os.path.dirname(self.config_path)
            if not os.path.exists(config_dir):
                os.makedirs(config_dir, exist_ok=True)
                
            with open(self.config_path, 'w') as f:
                # Don't save the password to disk
                save_config = {k: v for k, v in config.items() if k != 'password'}
                json.dump(save_config, f, indent=4)
        except Exception as e:
            logging.error(f"Error saving config: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value"""
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any) -> None:
        """Set a configuration value"""
        self.config[key] = value
        self.save_config(self.config)
    
    def interactive_setup(self) -> None:
        """Interactive setup for first run"""
        print("Mempool Partyline - First Time Setup")
        print("-" * 40)
        
        self.config['rpc_user'] = input(f"Bitcoin RPC Username [{self.config.get('rpc_user')}]: ") or self.config.get('rpc_user')
        self.config['rpc_password'] = getpass.getpass(f"Bitcoin RPC Password: ") or self.config.get('rpc_password')
        self.config['rpc_host'] = input(f"Bitcoin RPC Host [{self.config.get('rpc_host')}]: ") or self.config.get('rpc_host')
        self.config['rpc_port'] = input(f"Bitcoin RPC Port [{self.config.get('rpc_port')}]: ") or self.config.get('rpc_port')
        self.config['zmq_tx_endpoint'] = input(f"ZMQ TX Endpoint [{self.config.get('zmq_tx_endpoint')}]: ") or self.config.get('zmq_tx_endpoint')
        self.config['nickname'] = input(f"Your Nickname [{self.config.get('nickname')}]: ") or self.config.get('nickname')
        
        # Password for encryption - don't save this
        self.config['password'] = getpass.getpass("Encryption Password (shared with your contacts): ")
        
        self.save_config(self.config)
        print("Configuration saved!")


# --- Crypto Engine ---
class CryptoEngine:
    def __init__(self, password: str):
        self.password = password.encode('utf-8') if isinstance(password, str) else password
        self.key = self._derive_key(self.password)
        
    def _derive_key(self, password: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        salt = b'mempool_partyline_salt'  # In production, use a unique salt per user
        return PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
    
    def encrypt_message(self, message: str, sender: str) -> str:
        """Encrypt a message with sender metadata"""
        # Include sender and timestamp in the encrypted payload
        payload = {
            "sender": sender,
            "message": message,
            "timestamp": time.time()
        }
        
        # Encrypt the payload
        payload_bytes = json.dumps(payload).encode('utf-8')
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(payload_bytes)
        
        # Format for transmission
        result = {
            "nonce": base64.b64encode(cipher.nonce).decode(),
            "cipher": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(tag).decode()
        }
        return json.dumps(result)
    
    def decrypt_message(self, encrypted_str: str) -> Optional[Message]:
        """Decrypt a message and return a Message object if successful"""
        try:
            data = json.loads(encrypted_str)
            cipher = AES.new(
                self.key, 
                AES.MODE_EAX, 
                nonce=base64.b64decode(data['nonce'])
            )
            
            decrypted_bytes = cipher.decrypt_and_verify(
                base64.b64decode(data['cipher']), 
                base64.b64decode(data['tag'])
            )
            
            payload = json.loads(decrypted_bytes.decode('utf-8'))
            return Message(
                content=payload['message'],
                timestamp=payload['timestamp'],
                sender=payload.get('sender', 'Unknown')
            )
            
        except Exception as e:
            logging.debug(f"Decryption error: {e}")
            return None


# --- Bitcoin Interface ---
class BitcoinInterface:
    def __init__(self, config: Config):
        self.config = config
        self.rpc_url = (
            f"http://{config.get('rpc_user')}:{config.get('rpc_password')}"
            f"@{config.get('rpc_host')}:{config.get('rpc_port')}"
        )
        self.rpc_connection = self._connect()
        
    def _connect(self) -> AuthServiceProxy:
        """Connect to Bitcoin RPC"""
        try:
            return AuthServiceProxy(self.rpc_url)
        except Exception as e:
            logging.error(f"Failed to connect to Bitcoin node: {e}")
            raise RuntimeError(f"Bitcoin connection error: {e}")
    
    def create_op_return_tx(self, encrypted_msg: str) -> str:
        """Create and broadcast an OP_RETURN transaction with encrypted message"""
        try:
            # Ensure connection is fresh
            self.rpc_connection = self._connect()
            
            # Get available UTXOs
            utxos = self.rpc_connection.listunspent(0)
            if not utxos:
                raise RuntimeError("No UTXOs available for transaction")
            
            utxo = utxos[0]
            inputs = [{"txid": utxo["txid"], "vout": utxo["vout"]}]
            
            # Create OP_RETURN output
            hex_data = encrypted_msg.encode('utf-8').hex()
            outputs = {"data": hex_data}
            
            # Create and sign transaction
            raw_tx = self.rpc_connection.createrawtransaction(inputs, outputs)
            funded_tx = self.rpc_connection.fundrawtransaction(raw_tx)["hex"]
            signed_tx = self.rpc_connection.signrawtransactionwithwallet(funded_tx)["hex"]
            
            # Broadcast transaction
            txid = self.rpc_connection.sendrawtransaction(signed_tx)
            logging.info(f"Message sent via TXID: {txid}")
            return txid
            
        except Exception as e:
            logging.error(f"Transaction error: {e}")
            raise RuntimeError(f"Failed to create transaction: {e}")
    
    def get_transaction(self, txid: str) -> Dict[str, Any]:
        """Get transaction details by txid"""
        try:
            return self.rpc_connection.getrawtransaction(txid, True)
        except Exception as e:
            logging.error(f"Error getting transaction {txid}: {e}")
            return {}
    
    def get_mempool_transactions(self) -> List[Dict[str, Any]]:
        """Get all transactions in the mempool"""
        try:
            mempool = self.rpc_connection.getrawmempool()
            return [self.get_transaction(txid) for txid in mempool]
        except Exception as e:
            logging.error(f"Error getting mempool: {e}")
            return []
            

# --- Message Handler ---
class MessageHandler:
    def __init__(self, config: Config, crypto: CryptoEngine, bitcoin: BitcoinInterface):
        self.config = config
        self.crypto = crypto
        self.bitcoin = bitcoin
        self.message_history: List[Message] = []
        self.message_callback = None
        
    def set_message_callback(self, callback) -> None:
        """Set callback function for when new messages are received"""
        self.message_callback = callback
        
    def send_message(self, content: str) -> str:
        """Send a message to the mempool"""
        try:
            nickname = self.config.get('nickname', 'anonymous')
            encrypted = self.crypto.encrypt_message(content, nickname)
            txid = self.bitcoin.create_op_return_tx(encrypted)
            
            # Add to local message history
            msg = Message(
                content=content,
                timestamp=time.time(),
                sender=f"{nickname} (you)",
                txid=txid
            )
            self.message_history.append(msg)
            
            return txid
        except Exception as e:
            logging.error(f"Error sending message: {e}")
            raise RuntimeError(f"Failed to send message: {e}")
    
    def process_transaction(self, tx: Dict[str, Any]) -> Optional[Message]:
        """Process a transaction to extract and decrypt any messages"""
        try:
            txid = tx.get("txid", "unknown")
            
            for vout in tx.get("vout", []):
                script = vout.get("scriptPubKey", {})
                
                # Check if this is an OP_RETURN output
                if script.get("type") == "nulldata":
                    asm = script.get("asm", "")
                    parts = asm.split(" ")
                    
                    if len(parts) == 2 and parts[0] == "OP_RETURN":
                        try:
                            # Convert hex to string
                            payload_hex = parts[1]
                            payload = bytes.fromhex(payload_hex).decode('utf-8')
                            
                            # Try to decrypt
                            msg = self.crypto.decrypt_message(payload)
                            
                            if msg:
                                msg.txid = txid
                                self.message_history.append(msg)
                                logging.info(f"New message: {msg.formatted()}")
                                
                                # Notify via callback if set
                                if self.message_callback:
                                    self.message_callback(msg)
                                    
                                return msg
                        except Exception as e:
                            logging.debug(f"Failed to process potential message in {txid}: {e}")
            
            return None
            
        except Exception as e:
            logging.error(f"Error processing transaction: {e}")
            return None


# --- Mempool Listeners ---
class MempoolListener:
    """Base class for mempool listeners"""
    def __init__(self, config: Config, bitcoin: BitcoinInterface, handler: MessageHandler):
        self.config = config
        self.bitcoin = bitcoin
        self.handler = handler
        self.running = False
        self.thread = None
        
    def start(self) -> None:
        """Start the listener in a background thread"""
        if self.running:
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._run)
        self.thread.daemon = True
        self.thread.start()
        
    def stop(self) -> None:
        """Stop the listener"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
            
    def _run(self) -> None:
        """Main listener loop - override in subclasses"""
        raise NotImplementedError


class ZmqListener(MempoolListener):
    """ZMQ-based mempool listener"""
    def _run(self) -> None:
        """ZMQ listener main loop"""
        context = zmq.Context()
        socket = context.socket(zmq.SUB)
        
        try:
            socket.connect(self.config.get('zmq_tx_endpoint'))
            socket.setsockopt_string(zmq.SUBSCRIBE, "rawtx")
            logging.info(f"ZMQ listener started on {self.config.get('zmq_tx_endpoint')}")
            
            while self.running:
                try:
                    topic, msg = socket.recv_multipart(flags=zmq.NOBLOCK)
                    if topic == b"rawtx":
                        raw_tx = msg.hex()
                        decoded = self.bitcoin.rpc_connection.decoderawtransaction(raw_tx)
                        self.handler.process_transaction(decoded)
                except zmq.Again:
                    time.sleep(0.1)  # Don't burn CPU while waiting
                except Exception as e:
                    logging.error(f"ZMQ processing error: {e}")
                    time.sleep(1)  # Backoff on errors
                    
        except Exception as e:
            logging.error(f"ZMQ listener error: {e}")
        finally:
            socket.close()
            context.term()


class PollingListener(MempoolListener):
    """Polling-based mempool listener"""
    def _run(self) -> None:
        """Polling listener main loop"""
        logging.info(f"Polling listener started with interval {self.config.get('poll_interval')}s")
        processed_txids = set()
        
        while self.running:
            try:
                # Get all transactions in mempool
                mempool = self.bitcoin.rpc_connection.getrawmempool()
                
                # Process new transactions
                for txid in mempool:
                    if txid not in processed_txids:
                        tx = self.bitcoin.get_transaction(txid)
                        self.handler.process_transaction(tx)
                        processed_txids.add(txid)
                
                # Limit the size of processed_txids to prevent memory issues
                if len(processed_txids) > 10000:
                    processed_txids = set(list(processed_txids)[-5000:])
                    
                time.sleep(float(self.config.get('poll_interval')))
            except Exception as e:
                logging.error(f"Polling error: {e}")
                time.sleep(5)  # Back off on errors


# --- User Interface Classes ---
class BaseUI:
    """Base class for user interfaces"""
    def __init__(self, config: Config, handler: MessageHandler):
        self.config = config
        self.handler = handler
        
    def run(self) -> None:
        """Start the user interface"""
        raise NotImplementedError
        
    def display_message(self, message: Message) -> None:
        """Display a message"""
        raise NotImplementedError


class ConsoleUI(BaseUI):
    """Simple console-based user interface"""
    def run(self) -> None:
        """Run the console UI"""
        self.handler.set_message_callback(self.display_message)
        
        print(f"[Mempool Partyline] Logged in as: {self.config.get('nickname')}")
        print("Type your message, hit ENTER to send. CTRL+C to quit.")
        print('-' * 50)
        
        # Display recent message history
        if self.handler.message_history:
            print("Recent messages:")
            for msg in self.handler.message_history[-5:]:
                print(msg.formatted())
            print('-' * 50)
            
        try:
            while True:
                msg = input(">> ")
                if msg.strip():
                    txid = self.handler.send_message(msg)
                    print(f"Sent via TXID: {txid}")
        except KeyboardInterrupt:
            print("\n[!] Exiting Mempool Partyline")
            
    def display_message(self, message: Message) -> None:
        """Display an incoming message"""
        print(f"\r{message.formatted()}")
        print(">> ", end='', flush=True)


class CursesUI(BaseUI):
    """Curses-based TUI"""
    def __init__(self, config: Config, handler: MessageHandler):
        super().__init__(config, handler)
        self.stdscr = None
        self.input_win = None
        self.chat_win = None
        self.status_win = None
        self.input_buffer = ""
        self.cursor_x = 0
        
    def run(self) -> None:
        """Run the curses UI"""
        curses.wrapper(self._main)
        
    def _main(self, stdscr) -> None:
        """Main curses application"""
        self.stdscr = stdscr
        curses.curs_set(1)  # Show cursor
        curses.use_default_colors()
        
        # Set up colors
        curses.start_color()
        curses.init_pair(1, curses.COLOR_GREEN, -1)
        curses.init_pair(2, curses.COLOR_CYAN, -1)
        curses.init_pair(3, curses.COLOR_YELLOW, -1)
        
        # Set up windows
        self._setup_windows()
        
        # Register message callback
        self.handler.set_message_callback(self.display_message)
        
        # Main loop
        self._update_status("Connected")
        self._redraw()
        self._input_loop()
        
    def _setup_windows(self) -> None:
        """Set up the curses windows"""
        h, w = self.stdscr.getmaxyx()
        
        # Create windows
        self.chat_win = curses.newwin(h - 3, w, 0, 0)
        self.status_win = curses.newwin(1, w, h - 3, 0)
        self.input_win = curses.newwin(2, w, h - 2, 0)
        
        # Configure windows
        self.chat_win.scrollok(True)
        self.input_win.keypad(True)
        
        # Display message history
        self._display_history()
        
    def _display_history(self) -> None:
        """Display message history in chat window"""
        self.chat_win.clear()
        max_msgs = curses.LINES - 4
        history = self.handler.message_history[-max_msgs:] if self.handler.message_history else []
        
        for msg in history:
            self.display_message(msg, redraw=False)
            
        self.chat_win.refresh()
        
    def _update_status(self, status: str) -> None:
        """Update the status bar"""
        self.status_win.clear()
        nickname = self.config.get('nickname')
        status_text = f" [{nickname}] | {status}"
        self.status_win.addstr(0, 0, status_text, curses.A_REVERSE)
        self.status_win.refresh()
        
    def _input_loop(self) -> None:
        """Main input loop"""
        while True:
            # Draw input prompt
            self.input_win.clear()
            self.input_win.addstr(0, 0, ">> ")
            self.input_win.addstr(0, 3, self.input_buffer)
            self.input_win.move(0, 3 + self.cursor_x)
            self.input_win.refresh()
            
            # Get input
            try:
                ch = self.input_win.getch()
            except KeyboardInterrupt:
                break
                
            if ch == curses.KEY_ENTER or ch == 10 or ch == 13:
                # Send message on Enter
                if self.input_buffer.strip():
                    try:
                        self._update_status("Sending message...")
                        txid = self.handler.send_message(self.input_buffer)
                        self._update_status(f"Sent via TXID: {txid[:10]}...")
                    except Exception as e:
                        self._update_status(f"Error: {e}")
                    
                    self.input_buffer = ""
                    self.cursor_x = 0
                    
            elif ch == curses.KEY_BACKSPACE or ch == 127:
                # Delete character on Backspace
                if self.cursor_x > 0:
                    self.input_buffer = (
                        self.input_buffer[:self.cursor_x-1] + 
                        self.input_buffer[self.cursor_x:]
                    )
                    self.cursor_x -= 1
                    
            elif ch == curses.KEY_LEFT:
                # Move cursor left
                if self.cursor_x > 0:
                    self.cursor_x -= 1
                    
            elif ch == curses.KEY_RIGHT:
                # Move cursor right
                if self.cursor_x < len(self.input_buffer):
                    self.cursor_x += 1
                    
            elif ch == curses.KEY_HOME:
                # Move to start of line
                self.cursor_x = 0
                
            elif ch == curses.KEY_END:
                # Move to end of line
                self.cursor_x = len(self.input_buffer)
                
            elif 32 <= ch <= 126:
                # Add printable character to input
                self.input_buffer = (
                    self.input_buffer[:self.cursor_x] + 
                    chr(ch) + 
                    self.input_buffer[self.cursor_x:]
                )
                self.cursor_x += 1
        
        # Clean up on exit
        curses.endwin()
        
    def _redraw(self) -> None:
        """Redraw all windows"""
        h, w = self.stdscr.getmaxyx()
        
        # Resize windows if terminal size changed
        if self.chat_win.getmaxyx() != (h - 3, w):
            self._setup_windows()
        else:
            self.chat_win.refresh()
            self.status_win.refresh()
            self.input_win.refresh()
        
    def display_message(self, message: Message, redraw: bool = True) -> None:
        """Display a message in the chat window"""
        # Format the message
        timestamp = datetime.fromtimestamp(message.timestamp).strftime('%H:%M:%S')
        
        # Use colors for different message parts
        self.chat_win.addstr(f"[")
        self.chat_win.addstr(f"{timestamp}", curses.color_pair(1))
        self.chat_win.addstr(f"] ")
        self.chat_win.addstr(f"{message.sender}", curses.color_pair(2))
        self.chat_win.addstr(f": {message.content}\n")
        
        if redraw:
            self.chat_win.refresh()


# --- Main Application ---
class MempoolPartyline:
    def __init__(self):
        self.config = Config()
        self.setup_logging()
        
        # Check if first run
        if not os.path.exists(self.config.config_path):
            self.config.interactive_setup()
            
        # Initialize components
        password = self.config.get('password')
        if not password:
            password = getpass.getpass("Encryption Password: ")
            
        self.crypto = CryptoEngine(password)
        self.bitcoin = BitcoinInterface(self.config)
        self.handler = MessageHandler(self.config, self.crypto, self.bitcoin)
        
        # Initialize listeners
        self.zmq_listener = ZmqListener(self.config, self.bitcoin, self.handler)
        self.polling_listener = PollingListener(self.config, self.bitcoin, self.handler)
        
    def setup_logging(self) -> None:
        """Set up logging"""
        log_file = self.config.get('log_file')
        log_dir = os.path.dirname(log_file)
        
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
    def run_console(self) -> None:
        """Run the console interface"""
        # Start a listener
        try:
            self.zmq_listener.start()
        except Exception:
            logging.warning("ZMQ listener failed, falling back to polling")
            self.polling_listener.start()
            
        # Start the UI
        ui = ConsoleUI(self.config, self.handler)
        ui.run()
        
        # Cleanup
        self.zmq_listener.stop()
        self.polling_listener.stop()
        
    def run_tui(self) -> None:
        """Run the curses TUI"""
        # Start a listener
        try:
            self.zmq_listener.start()
        except Exception:
            logging.warning("ZMQ listener failed, falling back to polling")
            self.polling_listener.start()
            
        # Start the UI
        ui = CursesUI(self.config, self.handler)
        ui.run()
        
        # Cleanup
        self.zmq_listener.stop()
        self.polling_listener.stop()
        
    def run_daemon(self) -> None:
        """Run as a daemon (just listen for messages)"""
        print("Starting mempool partyline daemon...")
        print(f"Logging to {self.config.get('log_file')}")
        
        # Start the listener
        try:
            print("Starting ZMQ listener...")
            self.zmq_listener.start()
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping daemon...")
        except Exception as e:
            print(f"ZMQ listener error: {e}")
            print("Falling back to polling listener...")
            
            try:
                self.polling_listener.start()
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nStopping daemon...")
        finally:
            self.zmq_listener.stop()
            self.polling_listener.stop()
            

# --- Main Entry Point ---
def main():
    parser = argparse.ArgumentParser(description="Mempool Partyline - Anonymous Messaging via Bitcoin Mempool")
    parser.add_argument("--tui", action="store_true", help="Launch the curses-based UI")
    parser.add_argument("--daemon", action="store_true", help="Start as a daemon (just listen)")
    parser.add_argument("--setup", action="store_true", help="Run the setup wizard")
    args = parser.parse_args()
    
    app = MempoolPartyline()
    
    if args.setup:
        app.config.interactive_setup()
    elif args.daemon:
        app.run_daemon()
    elif args.tui:
        app.run_tui()
    else:
        app.run_console()


if __name__ == "__main__":
    main()
