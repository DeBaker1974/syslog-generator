# syslog_generator/config.py
"""Configuration loader and validator."""

import yaml
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class GeneratorConfig:
    rate: float = 10.0
    max_messages: int = 0
    duration: int = 0

@dataclass
class OutputConfig:
    mode: str = "console"
    syslog_host: str = "127.0.0.1"
    syslog_port: int = 514
    file_path: str = "./logs/syslog_output.log"
    file_rotation: bool = True
    max_file_size_mb: int = 100

@dataclass
class AppConfig:
    generator: GeneratorConfig = field(default_factory=GeneratorConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    message_profiles: Dict[str, bool] = field(default_factory=dict)
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    hosts: List[str] = field(default_factory=list)

def load_config(config_path: str = "config.yaml") -> AppConfig:
    """Load configuration from YAML file."""
    
    # Default configuration
    default_config = {
        'generator': {'rate': 10, 'max_messages': 0, 'duration': 0},
        'output': {
            'mode': 'console',
            'syslog_host': '127.0.0.1',
            'syslog_port': 514,
            'file_path': './logs/syslog_output.log',
            'file_rotation': True,
            'max_file_size_mb': 100
        },
        'message_profiles': {
            'auth_logs': True,
            'network_logs': True,
            'application_logs': True,
            'system_logs': True,
            'security_logs': True,
            'database_logs': True,
            'web_server_logs': True
        },
        'severity_distribution': {
            'emergency': 1, 'alert': 2, 'critical': 5, 'error': 15,
            'warning': 25, 'notice': 20, 'info': 25, 'debug': 7
        },
        'hosts': ['localhost']
    }
    
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            file_config = yaml.safe_load(f) or {}
        
        # Merge configurations
        for key in default_config:
            if key in file_config:
                if isinstance(default_config[key], dict):
                    default_config[key].update(file_config[key])
                else:
                    default_config[key] = file_config[key]
    
    return AppConfig(
        generator=GeneratorConfig(**default_config['generator']),
        output=OutputConfig(**default_config['output']),
        message_profiles=default_config['message_profiles'],
        severity_distribution=default_config['severity_distribution'],
        hosts=default_config['hosts']
    )
