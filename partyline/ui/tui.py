"""Curses-based TUI for Mempool Partyline"""

import curses
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import IntEnum

from partyline.protocol import EnvelopeV2, parse_envelope

logger = logging.getLogger(__name__)


class MessageType(IntEnum):
    """Message types for display"""
    INCOMING = 1
    OUTGOING = 2
    SYSTEM = 3
    ERROR = 4


class ColorScheme(IntEnum):
    """Color pairs for curses"""
    DEFAULT = 1
    INCOMING = 2
    OUTGOING = 3
    SYSTEM = 4
    ERROR = 5
    STATUS = 6
    INPUT = 7


@dataclass
class Message:
    """A chat message"""
    content: str
    sender: str
    msg_type: MessageType = MessageType.INCOMING
    timestamp: float = field(default_factory=time.time)

    def display_text(self) -> str:
        """Format message for display"""
        if self.msg_type == MessageType.INCOMING:
            return f"{self.sender}: {self.content}"
        elif self.msg_type == MessageType.OUTGOING:
            return f"me: {self.content}"
        elif self.msg_type == MessageType.SYSTEM:
            return f"[SYSTEM] {self.content}"
        elif self.msg_type == MessageType.ERROR:
            return f"[ERROR] {self.content}"
        return f"{self.sender}: {self.content}"


@dataclass
class UIState:
    """UI state management"""
    messages: list[Message] = field(default_factory=list)
    input_buffer: str = ""
    cursor_pos: int = 0
    scroll_offset: int = 0
    running: bool = True
    nickname: str = "anonymous"
    network: str = "testnet"
    connected: bool = False

    def add_message(self, msg: Message) -> None:
        """Add a message to the history"""
        self.messages.append(msg)

    def append_char(self, char: str) -> None:
        """Append character to input buffer"""
        self.input_buffer = (
            self.input_buffer[:self.cursor_pos]
            + char
            + self.input_buffer[self.cursor_pos:]
        )
        self.cursor_pos += 1

    def backspace(self) -> None:
        """Remove character before cursor"""
        if self.cursor_pos > 0:
            self.input_buffer = (
                self.input_buffer[:self.cursor_pos - 1]
                + self.input_buffer[self.cursor_pos:]
            )
            self.cursor_pos -= 1

    def clear_input(self) -> None:
        """Clear input buffer"""
        self.input_buffer = ""
        self.cursor_pos = 0

    def scroll_down(self) -> None:
        """Scroll down"""
        self.scroll_offset += 1

    def scroll_up(self) -> None:
        """Scroll up"""
        self.scroll_offset = max(0, self.scroll_offset - 1)

    def stop(self) -> None:
        """Stop the UI loop"""
        self.running = False

    def get_visible_messages(self, screen_height: int) -> list[Message]:
        """Get messages visible in the message area"""
        # Message area takes screen_height - 4 lines (status bar, input, borders)
        msg_area_height = max(1, screen_height - 4)
        start = self.scroll_offset
        end = start + msg_area_height
        return self.messages[start:end]

    def get_total_messages(self) -> int:
        """Get total message count"""
        return len(self.messages)

    def receive_system_message(self, content: str) -> None:
        """Append a system notice to the history."""
        self.messages.append(
            Message(content=content, sender="system", msg_type=MessageType.SYSTEM)
        )


class MessageQueue:
    """Thread-safe in-memory message queue."""

    def __init__(self) -> None:
        self._queue: deque[bytes] = deque()
        self._lock = threading.Lock()

    def put(self, message: bytes) -> None:
        """Add a message to the queue."""
        with self._lock:
            self._queue.append(message)

    def get(self) -> bytes | None:
        """Remove and return the oldest message, or None if empty."""
        with self._lock:
            if self._queue:
                return self._queue.popleft()
            return None

    def peek(self) -> bytes | None:
        """Return the oldest message without removing it, or None if empty."""
        with self._lock:
            return self._queue[0] if self._queue else None

    def clear(self) -> None:
        """Remove all messages from the queue."""
        with self._lock:
            self._queue.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._queue)


class TUIMessageHandler:
    """Handles incoming messages for the TUI."""

    def __init__(self, queue: MessageQueue, ui_state: UIState) -> None:
        self.queue = queue
        self.ui_state = ui_state

    def process_messages(self) -> None:
        """Process all messages currently in the queue."""
        while True:
            msg_bytes = self.queue.get()
            if msg_bytes is None:
                break
            self._handle_message(msg_bytes)

    def _handle_message(self, msg_bytes: bytes) -> None:
        """Parse protocol envelope and add display message."""
        try:
            envelope = parse_envelope(msg_bytes)
            if isinstance(envelope, EnvelopeV2):
                msg = envelope
                if msg.msg_type.name == "TEXT":
                    display_msg = Message(
                        content=msg.payload,
                        sender=msg.sender_id or "anonymous",
                        msg_type=MessageType.INCOMING,
                    )
                    self.ui_state.add_message(display_msg)
                elif msg.msg_type.name == "HANDSHAKE_RESP":
                    self.ui_state.receive_system_message(
                        f"Handshake completed with {msg.sender_id or 'peer'}"
                    )
                elif msg.msg_type.name == "HANDSHAKE_INIT":
                    self.ui_state.receive_system_message(
                        f"Handshake initiated from {msg.sender_id or 'peer'}"
                    )
            # LegacyEnvelope handled by parse_envelope conversion
        except Exception as e:  # noqa: BLE001 - UI loop must not crash on unexpected input
            logger.error("Failed to process message: %s", e)


class TUI:
    """Curses-based TUI for Mempool Partyline"""

    def __init__(self, stdscr: curses.window, init_curses: bool = True) -> None:
        self.stdscr = stdscr
        self.state = UIState()
        self._colors_ready = False
        if init_curses:
            self._setup_screen()
            self._setup_colors()
            self._colors_ready = True

    def _setup_screen(self) -> None:
        """Configure curses screen"""
        self.stdscr.keypad(True)
        self.stdscr.nodelay(True)
        if self._colors_ready:
            curses.curs_set(1)  # Show cursor
        curses.noecho()
        curses.cbreak()

    def _setup_colors(self) -> None:
        """Initialize color pairs"""
        curses.start_color()
        # Define color pairs after calling start_color
        curses.init_pair(ColorScheme.DEFAULT, curses.COLOR_WHITE, -1)
        curses.init_pair(ColorScheme.INCOMING, curses.COLOR_GREEN, -1)
        curses.init_pair(ColorScheme.OUTGOING, curses.COLOR_BLUE, -1)
        curses.init_pair(ColorScheme.SYSTEM, curses.COLOR_YELLOW, -1)
        curses.init_pair(ColorScheme.ERROR, curses.COLOR_RED, -1)
        curses.init_pair(ColorScheme.STATUS, curses.COLOR_CYAN, -1)
        curses.init_pair(ColorScheme.INPUT, curses.COLOR_WHITE, curses.COLOR_BLACK)

    def draw(self) -> None:
        """Draw the UI"""
        self.stdscr.clear()
        height, width = self.stdscr.getmaxyx()

        # Draw status bar
        self._draw_status_bar(height, width)

        # Draw message area
        self._draw_messages(height, width)

        # Draw input area
        self._draw_input(height, width)

        self.stdscr.refresh()

    def _draw_status_bar(self, height: int, width: int) -> None:
        """Draw status bar at top"""
        status = f"Mempool Partyline | {self.state.nickname} | {self.state.network}"
        if self.state.connected:
            status += " | CONNECTED"
        else:
            status += " | DISCONNECTED"

        try:
            self.stdscr.addstr(0, 0, status[:width - 1], curses.color_pair(ColorScheme.STATUS))
        except curses.error:
            pass

    def _draw_messages(self, height: int, width: int) -> None:
        """Draw message list"""
        msg_area_start = 1
        msg_area_height = height - 4  # Leave room for status bar, input, and borders

        visible_messages = self.state.get_visible_messages(height)

        for idx, msg in enumerate(visible_messages):
            y = msg_area_start + idx
            if y >= msg_area_start + msg_area_height:
                break

            text = msg.display_text()
            color = self._get_message_color(msg)

            try:
                self.stdscr.addstr(y, 1, text[:width - 2], curses.color_pair(color))
            except curses.error:
                pass

    def _draw_input(self, height: int, width: int) -> None:
        """Draw input area at bottom"""
        input_y = height - 2

        # Draw input prompt and buffer
        prompt = "> "
        try:
            self.stdscr.addstr(input_y, 0, prompt, curses.color_pair(ColorScheme.INPUT))
            self.stdscr.addstr(
                input_y, len(prompt),
                self.state.input_buffer[:width - len(prompt) - 1],
                curses.color_pair(ColorScheme.INPUT)
            )
            # Position cursor
            cursor_x = len(prompt) + self.state.cursor_pos
            self.stdscr.move(input_y, min(cursor_x, width - 1))
        except curses.error:
            pass

    def _get_message_color(self, msg: Message) -> int:
        """Get color pair for message type"""
        if msg.msg_type == MessageType.INCOMING:
            return ColorScheme.INCOMING
        elif msg.msg_type == MessageType.OUTGOING:
            return ColorScheme.OUTGOING
        elif msg.msg_type == MessageType.SYSTEM:
            return ColorScheme.SYSTEM
        elif msg.msg_type == MessageType.ERROR:
            return ColorScheme.ERROR
        return ColorScheme.DEFAULT

    def handle_input(self, key: int) -> None:
        """Handle keyboard input"""
        if key == 27 or key == 3:  # Escape
            self.state.stop()
        elif key == 10 or key == 13:  # Enter
            self._send_message()
        elif key == 127 or key == curses.KEY_BACKSPACE:  # Backspace
            self.state.backspace()
        elif key == curses.KEY_UP:
            self.state.scroll_up()
        elif key == curses.KEY_DOWN:
            self.state.scroll_down()
        elif key == curses.KEY_PPAGE:  # Page Up
            for _ in range(10):
                self.state.scroll_up()
        elif key == curses.KEY_NPAGE:  # Page Down
            for _ in range(10):
                self.state.scroll_down()
        elif 32 <= key <= 126:  # Printable ASCII
            self.state.append_char(chr(key))

    def _send_message(self) -> None:
        """Send message from input buffer"""
        msg_text = self.state.input_buffer.strip()
        if msg_text:
            self.send_message(msg_text)
            self.state.clear_input()

    def send_message(self, text: str) -> None:
        """Programmatically send a message"""
        if not text or not text.strip():
            return
        msg = Message(
            content=text,
            sender=self.state.nickname,
            msg_type=MessageType.OUTGOING,
        )
        self.state.add_message(msg)

    def receive_message(self, content: str, sender: str) -> None:
        """Receive a message from another user"""
        msg = Message(
            content=content,
            sender=sender,
            msg_type=MessageType.INCOMING,
        )
        self.state.add_message(msg)

    def receive_system_message(self, content: str) -> None:
        """Receive a system message"""
        msg = Message(
            content=content,
            sender="system",
            msg_type=MessageType.SYSTEM,
        )
        self.state.add_message(msg)

    def run(self) -> None:
        """Main UI loop"""
        while self.state.running:
            self.draw()

            try:
                key = self.stdscr.getch()
                if key != -1:
                    self.handle_input(key)
            except KeyboardInterrupt:
                self.state.stop()
                break
            except Exception:  # noqa: BLE001,S110 - UI loop must not crash on unexpected input
                # Ignore other exceptions, continue loop
                pass

        # Cleanup - curses.wrapper handles cbreak()/nocbreak()/endwin()
        # when run() is invoked through run_tui(). For standalone use,
        # the caller is responsible for terminal restoration.


def run_tui(nickname: str = "anonymous", network: str = "testnet") -> None:
    """Entry point for running the TUI"""
    def _main(stdscr: curses.window) -> None:
        tui = TUI(stdscr)
        tui.state.nickname = nickname
        tui.state.network = network
        tui.state.connected = True
        tui.receive_system_message(f"Welcome to Mempool Partyline, {nickname}!")
        tui.run()

    curses.wrapper(_main)