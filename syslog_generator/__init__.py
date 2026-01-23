# syslog_generator/__init__.py
"""
Syslog Generator - A tool for generating realistic syslog messages.

This package provides tools for generating various types of syslog messages
for testing log ingestion pipelines, Elasticsearch, Logstash, and Kibana.
"""

__version__ = '1.0.0'
__author__ = 'Your Name'

from .generator import SyslogGenerator, BurstGenerator
from .config import (
    load_config,
    Config,
    ESTargetConfig,
    OutputConfig,
    GeneratorConfig,
    discover_es_targets,
    get_active_es_target
)
from .templates import MessageTemplates
from .senders import (
    MessageSender,
    ConsoleSender,
    UDPSender,
    TCPSender,
    FileSender,
    create_sender
)
from .es_client import ESClient

# Backward compatibility alias
AppConfig = Config

__all__ = [
    # Generator
    'SyslogGenerator',
    'BurstGenerator',
    # Config
    'load_config',
    'Config',
    'AppConfig',  # Backward compatibility
    'ESTargetConfig',
    'OutputConfig',
    'GeneratorConfig',
    'discover_es_targets',
    'get_active_es_target',
    # Templates
    'MessageTemplates',
    # Senders
    'MessageSender',
    'ConsoleSender',
    'UDPSender',
    'TCPSender',
    'FileSender',
    'create_sender',
    # ES Client
    'ESClient',
]
