# syslog_generator/__init__.py
"""
Syslog Generator - A tool for generating realistic syslog messages.

This package provides tools for generating various types of syslog messages
for testing log ingestion pipelines, Elasticsearch, Logstash, and Kibana.
"""

__version__ = '1.0.0'
__author__ = 'Your Name'

from .generator import SyslogGenerator, BurstGenerator
from .config import load_config, AppConfig
from .templates import MessageTemplates
from .senders import (
    MessageSender,
    ConsoleSender,
    UDPSender,
    TCPSender,
    FileSender,
    create_sender
)

__all__ = [
    'SyslogGenerator',
    'BurstGenerator',
    'load_config',
    'AppConfig',
    'MessageTemplates',
    'MessageSender',
    'ConsoleSender',
    'UDPSender',
    'TCPSender',
    'FileSender',
    'create_sender',
]
