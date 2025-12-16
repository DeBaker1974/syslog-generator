# syslog_generator/senders.py
"""Output handlers for sending syslog messages."""

import socket
import os
import logging
from datetime import datetime
from typing import Dict, Optional, Protocol
from abc import ABC, abstractmethod
from colorama import Fore, Style, init

# Initialize colorama for Windows compatibility
init(autoreset=True)

class MessageSender(ABC):
    """Abstract base class for message senders."""
    
    @abstractmethod
    def send(self, message_data: Dict) -> bool:
        """Send a syslog message."""
        pass
    
    @abstractmethod
    def close(self) -> None:
        """Clean up resources."""
        pass
    
    def format_rfc3164(self, data: Dict) -> str:
        """Format message in RFC 3164 (BSD syslog) format."""
        pri = data.get('priority', 13)
        timestamp = data.get('timestamp', datetime.now().strftime("%b %d %H:%M:%S"))
        host = data.get('host', 'localhost')
        app = data.get('app', 'unknown')
        pid = data.get('pid')
        message = data.get('message', '')
        
        if pid:
            return f"<{pri}>{timestamp} {host} {app}[{pid}]: {message}"
        else:
            return f"<{pri}>{timestamp} {host} {app}: {message}"
    
    def format_rfc5424(self, data: Dict) -> str:
        """Format message in RFC 5424 (modern syslog) format."""
        pri = data.get('priority', 13)
        version = 1
        timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        host = data.get('host', 'localhost')
        app = data.get('app', 'unknown')
        pid = data.get('pid', '-')
        msgid = data.get('msgid', '-')
        structured_data = '-'
        message = data.get('message', '')
        
        return f"<{pri}>{version} {timestamp} {host} {app} {pid} {msgid} {structured_data} {message}"


class ConsoleSender(MessageSender):
    """Send messages to console with color coding."""
    
    SEVERITY_COLORS = {
        'emergency': Fore.MAGENTA + Style.BRIGHT,
        'alert': Fore.MAGENTA,
        'critical': Fore.RED + Style.BRIGHT,
        'error': Fore.RED,
        'warning': Fore.YELLOW,
        'notice': Fore.CYAN,
        'info': Fore.GREEN,
        'debug': Fore.WHITE + Style.DIM,
    }
    
    def send(self, message_data: Dict) -> bool:
        """Print message to console with colors."""
        try:
            severity = message_data.get('severity', 'info')
            color = self.SEVERITY_COLORS.get(severity, Fore.WHITE)
            formatted = self.format_rfc3164(message_data)
            
            # Add category tag
            category = message_data.get('category', 'unknown')
            category_str = f"[{category.upper():^12}]"
            
            print(f"{color}{category_str} {formatted}{Style.RESET_ALL}")
            return True
        except Exception as e:
            logging.error(f"Console send error: {e}")
            return False
    
    def close(self) -> None:
        """No cleanup needed for console."""
        pass


class UDPSender(MessageSender):
    """Send messages via UDP to syslog server."""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 514):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        logging.info(f"UDP sender initialized: {host}:{port}")
    
    def send(self, message_data: Dict) -> bool:
        """Send message via UDP."""
        try:
            formatted = self.format_rfc3164(message_data)
            self.socket.sendto(formatted.encode('utf-8'), (self.host, self.port))
            return True
        except Exception as e:
            logging.error(f"UDP send error: {e}")
            return False
    
    def close(self) -> None:
        """Close the UDP socket."""
        if self.socket:
            self.socket.close()


class TCPSender(MessageSender):
    """Send messages via TCP to syslog server."""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 514):
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
        self._connect()
    
    def _connect(self) -> None:
        """Establish TCP connection."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            logging.info(f"TCP connection established: {self.host}:{self.port}")
        except Exception as e:
            logging.error(f"TCP connection failed: {e}")
            self.socket = None
    
    def send(self, message_data: Dict) -> bool:
        """Send message via TCP."""
        if not self.socket:
            self._connect()
            if not self.socket:
                return False
        
        try:
            formatted = self.format_rfc3164(message_data) + "\n"
            self.socket.sendall(formatted.encode('utf-8'))
            return True
        except (BrokenPipeError, ConnectionResetError) as e:
            logging.warning(f"TCP connection lost, reconnecting: {e}")
            self._connect()
            return False
        except Exception as e:
            logging.error(f"TCP send error: {e}")
            return False
    
    def close(self) -> None:
        """Close the TCP socket."""
        if self.socket:
            self.socket.close()
            self.socket = None


class FileSender(MessageSender):
    """Write messages to a log file with optional rotation."""
    
    def __init__(self, file_path: str, max_size_mb: int = 100, rotation: bool = True):
        self.file_path = file_path
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.rotation = rotation
        self.file_handle = None
        self._ensure_directory()
        self._open_file()
    
    def _ensure_directory(self) -> None:
        """Ensure the log directory exists."""
        directory = os.path.dirname(self.file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
    
    def _open_file(self) -> None:
        """Open the log file for appending."""
        self.file_handle = open(self.file_path, 'a', encoding='utf-8')
        logging.info(f"File sender initialized: {self.file_path}")
    
    def _rotate_if_needed(self) -> None:
        """Rotate log file if it exceeds max size."""
        if not self.rotation:
            return
        
        try:
            if os.path.getsize(self.file_path) > self.max_size_bytes:
                self.file_handle.close()
                
                # Rotate existing files
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                rotated_path = f"{self.file_path}.{timestamp}"
                os.rename(self.file_path, rotated_path)
                
                self._open_file()
                logging.info(f"Log rotated to: {rotated_path}")
        except FileNotFoundError:
            pass
    
    def send(self, message_data: Dict) -> bool:
        """Write message to file."""
        try:
            self._rotate_if_needed()
            formatted = self.format_rfc3164(message_data)
            self.file_handle.write(formatted + "\n")
            self.file_handle.flush()
            return True
        except Exception as e:
            logging.error(f"File write error: {e}")
            return False
    
    def close(self) -> None:
        """Close the file handle."""
        if self.file_handle:
            self.file_handle.close()


class MultiSender(MessageSender):
    """Send messages to multiple destinations."""
    
    def __init__(self, senders: list):
        self.senders = senders
    
    def send(self, message_data: Dict) -> bool:
        """Send message to all configured senders."""
        results = [sender.send(message_data) for sender in self.senders]
        return all(results)
    
    def close(self) -> None:
        """Close all senders."""
        for sender in self.senders:
            sender.close()


# syslog_generator/senders.py (continued - completing the create_sender function)

def create_sender(config) -> MessageSender:
    """Factory function to create appropriate sender based on config."""
    mode = config.output.mode.lower()
    
    if mode == 'console':
        return ConsoleSender()
    elif mode == 'udp':
        return UDPSender(config.output.syslog_host, config.output.syslog_port)
    elif mode == 'tcp':
        return TCPSender(config.output.syslog_host, config.output.syslog_port)
    elif mode == 'file':
        return FileSender(
            config.output.file_path,
            config.output.max_file_size_mb,
            config.output.file_rotation
        )
    elif mode == 'all':
        senders = [
            ConsoleSender(),
            UDPSender(config.output.syslog_host, config.output.syslog_port),
            FileSender(
                config.output.file_path,
                config.output.max_file_size_mb,
                config.output.file_rotation
            )
        ]
        return MultiSender(senders)
    else:
        logging.warning(f"Unknown output mode '{mode}', defaulting to console")
        return ConsoleSender()

