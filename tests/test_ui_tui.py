"""Tests for the curses-based TUI"""

from unittest.mock import MagicMock, patch

import pytest

from partyline.ui.tui import (
    TUI,
    ColorScheme,
    Message,
    MessageType,
    UIState,
)


class TestMessage:
    """Test Message dataclass"""

    def test_create_message(self):
        """Test creating a message"""
        msg = Message(
            content="Hello, world!",
            sender="alice",
            msg_type=MessageType.INCOMING,
            timestamp=1234567890.0,
        )
        assert msg.content == "Hello, world!"
        assert msg.sender == "alice"
        assert msg.msg_type == MessageType.INCOMING
        assert msg.timestamp == 1234567890.0

    def test_message_defaults(self):
        """Test message defaults"""
        msg = Message(content="test", sender="system", msg_type=MessageType.SYSTEM)
        assert msg.timestamp > 0
        assert msg.msg_type == MessageType.SYSTEM

    def test_message_display_text(self):
        """Test message display formatting"""
        msg = Message(
            content="Hello",
            sender="alice",
            msg_type=MessageType.INCOMING,
            timestamp=1000000000.0,
        )
        display = msg.display_text()
        assert "alice" in display
        assert "Hello" in display

    def test_message_display_text_outgoing(self):
        """Test outgoing message display"""
        msg = Message(
            content="Hi there",
            sender="me",
            msg_type=MessageType.OUTGOING,
            timestamp=1000000000.0,
        )
        display = msg.display_text()
        assert "me" in display
        assert "Hi there" in display


class TestColorScheme:
    """Test ColorScheme enum"""

    def test_color_values(self):
        """Test color values are valid curses colors"""
        assert ColorScheme.DEFAULT.value >= 0
        assert ColorScheme.INCOMING.value >= 0
        assert ColorScheme.OUTGOING.value >= 0
        assert ColorScheme.SYSTEM.value >= 0
        assert ColorScheme.ERROR.value >= 0
        assert ColorScheme.STATUS.value >= 0


class TestUIState:
    """Test UIState dataclass"""

    def test_initial_state(self):
        """Test initial UI state"""
        state = UIState()
        assert state.messages == []
        assert state.input_buffer == ""
        assert state.cursor_pos == 0
        assert state.scroll_offset == 0
        assert state.running is True

    def test_add_message(self):
        """Test adding a message to state"""
        state = UIState()
        msg = Message(content="test", sender="alice", msg_type=MessageType.INCOMING)
        state.add_message(msg)
        assert len(state.messages) == 1
        assert state.messages[0] == msg

    def test_add_message_maintains_order(self):
        """Test messages are added in order"""
        state = UIState()
        msg1 = Message(content="first", sender="a", msg_type=MessageType.INCOMING)
        msg2 = Message(content="second", sender="b", msg_type=MessageType.OUTGOING)
        state.add_message(msg1)
        state.add_message(msg2)
        assert len(state.messages) == 2
        assert state.messages[0] == msg1
        assert state.messages[1] == msg2

    def test_input_buffer_append(self):
        """Test appending to input buffer"""
        state = UIState()
        state.append_char("H")
        state.append_char("i")
        assert state.input_buffer == "Hi"
        assert state.cursor_pos == 2

    def test_input_buffer_backspace(self):
        """Test backspace in input buffer"""
        state = UIState()
        state.append_char("H")
        state.append_char("i")
        state.backspace()
        assert state.input_buffer == "H"
        assert state.cursor_pos == 1

    def test_input_buffer_backspace_empty(self):
        """Test backspace on empty buffer"""
        state = UIState()
        state.backspace()
        assert state.input_buffer == ""
        assert state.cursor_pos == 0

    def test_input_buffer_clear(self):
        """Test clearing input buffer"""
        state = UIState()
        state.append_char("test")
        state.clear_input()
        assert state.input_buffer == ""
        assert state.cursor_pos == 0

    def test_scroll_down(self):
        """Test scrolling down"""
        state = UIState()
        state.scroll_offset = 0
        state.scroll_down()
        assert state.scroll_offset == 1

    def test_scroll_up(self):
        """Test scrolling up"""
        state = UIState()
        state.scroll_offset = 5
        state.scroll_up()
        assert state.scroll_offset == 4

    def test_scroll_up_min_zero(self):
        """Test scroll doesn't go below 0"""
        state = UIState()
        state.scroll_offset = 0
        state.scroll_up()
        assert state.scroll_offset == 0

    def test_stop(self):
        """Test stopping the UI"""
        state = UIState()
        assert state.running is True
        state.stop()
        assert state.running is False


class TestTUI:
    """Test TUI class"""

    @pytest.fixture
    def mock_stdscr(self):
        """Create a mock curses screen"""
        mock = MagicMock()
        mock.getmaxyx.return_value = (24, 80)
        return mock

    def test_tui_initialization(self, mock_stdscr):
        """Test TUI initializes correctly"""
        tui = TUI(mock_stdscr, init_curses=False)
        assert tui.stdscr == mock_stdscr
        assert tui.state is not None
        assert tui.state.running is True

    def test_tui_draw(self, mock_stdscr):
        """Test TUI draw method"""
        tui = TUI(mock_stdscr, init_curses=False)
        tui.draw()
        # Should have called clear and refresh
        mock_stdscr.clear.assert_called()
        mock_stdscr.refresh.assert_called()

    def test_tui_draw_with_messages(self, mock_stdscr):
        """Test TUI draw with messages"""
        tui = TUI(mock_stdscr, init_curses=False)
        msg = Message(content="Hello", sender="alice", msg_type=MessageType.INCOMING)
        tui.state.add_message(msg)
        tui.draw()
        # Should render without error
        mock_stdscr.clear.assert_called()

    def test_tui_handle_input_char(self, mock_stdscr):
        """Test handling character input"""
        tui = TUI(mock_stdscr, init_curses=False)
        tui.handle_input(ord("H"))
        assert tui.state.input_buffer == "H"

    def test_tui_handle_input_enter(self, mock_stdscr):
        """Test handling Enter key"""
        tui = TUI(mock_stdscr, init_curses=False)
        tui.state.append_char("test")
        with patch.object(tui, 'send_message') as mock_send:
            tui.handle_input(10)  # Enter key
            mock_send.assert_called_once_with("test")

    def test_tui_handle_input_backspace(self, mock_stdscr):
        """Test handling backspace"""
        tui = TUI(mock_stdscr, init_curses=False)
        tui.state.append_char("H")
        tui.state.append_char("i")
        tui.handle_input(127)  # Backspace
        assert tui.state.input_buffer == "H"

    def test_tui_handle_input_escape(self, mock_stdscr):
        """Test handling Escape key"""
        tui = TUI(mock_stdscr, init_curses=False)
        tui.handle_input(27)  # Escape
        assert tui.state.running is False

    def test_tui_handle_input_ctrl_c(self, mock_stdscr):
        """Test handling Ctrl+C"""
        tui = TUI(mock_stdscr, init_curses=False)
        tui.handle_input(3)  # Ctrl+C
        assert tui.state.running is False

    def test_tui_send_message(self, mock_stdscr):
        """Test sending a message"""
        tui = TUI(mock_stdscr, init_curses=False)
        with patch("partyline.ui.tui.MessageSender") as mock_sender_cls:
            mock_sender_cls.return_value.send.return_value = MagicMock(txid="abc123", error=None)
            tui.send_message("Hello, world!")
        # Should add message to state
        assert len(tui.state.messages) == 1
        assert tui.state.messages[0].content == "Hello, world!"
        assert tui.state.messages[0].msg_type == MessageType.OUTGOING

    def test_tui_send_message_error(self, mock_stdscr):
        """Test sending a message surfaces transport errors as system message"""
        tui = TUI(mock_stdscr, init_curses=False)
        with patch("partyline.ui.tui.MessageSender") as mock_sender_cls:
            mock_sender_cls.return_value.send.return_value = MagicMock(
                txid=None, error="RPC connection refused"
            )
            tui.send_message("Hello")
        assert len(tui.state.messages) == 1
        assert tui.state.messages[0].msg_type == MessageType.SYSTEM
        assert "RPC connection refused" in tui.state.messages[0].content

    def test_tui_send_empty_message(self, mock_stdscr):
        """Test sending empty message is ignored"""
        tui = TUI(mock_stdscr, init_curses=False)
        tui.send_message("")
        assert len(tui.state.messages) == 0

    def test_tui_receive_message(self, mock_stdscr):
        """Test receiving a message"""
        tui = TUI(mock_stdscr, init_curses=False)
        tui.receive_message("Hello from alice", "alice")
        assert len(tui.state.messages) == 1
        assert tui.state.messages[0].content == "Hello from alice"
        assert tui.state.messages[0].sender == "alice"
        assert tui.state.messages[0].msg_type == MessageType.INCOMING

    def test_tui_receive_system_message(self, mock_stdscr):
        """Test receiving system message"""
        tui = TUI(mock_stdscr, init_curses=False)
        tui.receive_system_message("Connected to network")
        assert len(tui.state.messages) == 1
        assert tui.state.messages[0].msg_type == MessageType.SYSTEM
        assert tui.state.messages[0].content == "Connected to network"

    def test_tui_run_loop(self, mock_stdscr):
        """Test main run loop"""
        tui = TUI(mock_stdscr, init_curses=False)
        # Mock getch to return Escape after one iteration
        mock_stdscr.getch.side_effect = [ord("a"), 27]
        tui.run()
        # Should have drawn at least once
        assert mock_stdscr.clear.called

    def test_tui_resize(self, mock_stdscr):
        """Test handling terminal resize"""
        tui = TUI(mock_stdscr, init_curses=False)
        mock_stdscr.getmaxyx.return_value = (30, 100)
        tui.draw()  # Should not raise
        mock_stdscr.clear.assert_called()


class TestMessageDisplay:
    """Test message display formatting"""

    def test_incoming_message_prefix(self):
        """Test incoming message has sender prefix"""
        msg = Message(
            content="Hello",
            sender="alice",
            msg_type=MessageType.INCOMING,
            timestamp=1000000000.0,
        )
        display = msg.display_text()
        assert display.startswith("alice:")

    def test_outgoing_message_prefix(self):
        """Test outgoing message has 'me' prefix"""
        msg = Message(
            content="Hi",
            sender="me",
            msg_type=MessageType.OUTGOING,
            timestamp=1000000000.0,
        )
        display = msg.display_text()
        assert display.startswith("me:")

    def test_system_message_prefix(self):
        """Test system message has system prefix"""
        msg = Message(
            content="Connected",
            sender="system",
            msg_type=MessageType.SYSTEM,
            timestamp=1000000000.0,
        )
        display = msg.display_text()
        assert display.startswith("[SYSTEM]")

    def test_error_message_prefix(self):
        """Test error message has error prefix"""
        msg = Message(
            content="Error occurred",
            sender="system",
            msg_type=MessageType.ERROR,
            timestamp=1000000000.0,
        )
        display = msg.display_text()
        assert display.startswith("[ERROR]")


class TestUIStateMessages:
    """Test UIState message handling"""

    def test_get_visible_messages(self):
        """Test getting visible messages with scroll"""
        state = UIState()
        for i in range(20):
            msg = Message(content=f"msg {i}", sender="a", msg_type=MessageType.INCOMING)
            state.add_message(msg)
        # Default screen height is 24, status bar takes 2 lines
        visible = state.get_visible_messages(screen_height=24)
        assert len(visible) <= 20

    def test_get_visible_messages_with_scroll(self):
        """Test visible messages respects scroll offset"""
        state = UIState()
        for i in range(30):
            msg = Message(content=f"msg {i}", sender="a", msg_type=MessageType.INCOMING)
            state.add_message(msg)
        state.scroll_offset = 10
        visible = state.get_visible_messages(screen_height=20)
        assert len(visible) <= 20