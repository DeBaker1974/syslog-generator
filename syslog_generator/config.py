# syslog_generator/config.py
"""Configuration loader with multi-target Elasticsearch support."""

import os
import logging
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Load .env file
try:
    from dotenv import load_dotenv

    env_paths = [
        Path('.env'),
        Path(__file__).parent.parent / '.env',
        Path.home() / '.syslog-generator.env',
    ]

    for env_path in env_paths:
        if env_path.exists():
            load_dotenv(env_path)
            break
    else:
        load_dotenv()

except ImportError:
    pass


def get_env(key: str, default: any = None, cast: type = str) -> any:
    """Get environment variable with type casting."""
    value = os.getenv(key)

    if value is None:
        return default

    if cast == bool:
        return value.lower() in ('true', '1', 'yes', 'on')

    try:
        return cast(value)
    except (ValueError, TypeError):
        return default


@dataclass
class GeneratorConfig:
    rate: float = 10.0
    max_messages: int = 0
    duration: int = 0
    burst_mode: bool = False
    scenario: Optional[str] = None


@dataclass
class OutputConfig:
    mode: str = "console"
    syslog_host: str = "127.0.0.1"
    syslog_port: int = 514
    file_path: str = "./logs/syslog_output.log"
    file_rotation: bool = True
    max_file_size_mb: int = 100


@dataclass
class ElasticsearchConfig:
    """Elasticsearch connection configuration."""
    enabled: bool = False
    target: str = ""
    url: str = ""
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    index: str = "logs"  # Changed from index_prefix
    verify_certs: bool = True
    ca_certs: Optional[str] = None
    batch_size: int = 100
    flush_interval: float = 5.0


@dataclass
class AppConfig:
    generator: GeneratorConfig = field(default_factory=GeneratorConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    elasticsearch: ElasticsearchConfig = field(default_factory=ElasticsearchConfig)
    message_profiles: Dict[str, bool] = field(default_factory=dict)
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    hosts: List[str] = field(default_factory=list)
    _es_client: Optional[object] = field(default=None, repr=False)

    @property
    def es_client(self):
        """Get ES client."""
        return self._es_client

    @es_client.setter
    def es_client(self, value):
        """Set ES client."""
        self._es_client = value

    def close(self):
        """Clean up resources."""
        if self._es_client is not None:
            self._es_client.close()
            self._es_client = None


def _create_es_client(es_config: ElasticsearchConfig):
    """Create ES client from config."""
    # Import here to avoid circular imports
    from .es_client import ESClient

    if not es_config.url:
        logger.warning("ES enabled but no URL configured")
        return None

    try:
        return ESClient(
            url=es_config.url,
            api_key=es_config.api_key,
            username=es_config.username,
            password=es_config.password,
            index=es_config.index,
            buffer_size=es_config.batch_size,
            verify_certs=es_config.verify_certs
        )
    except Exception as e:
        logger.error(f"Failed to create ES client: {e}")
        return None


def _load_es_target_config() -> Dict[str, any]:
    """Load Elasticsearch configuration from active target."""

    # Get active target
    target = os.getenv('ES_TARGET', '').lower()

    if not target:
        # Fallback to legacy single-target config
        return {
            'enabled': get_env('ES_ENABLED', False, bool),
            'target': 'default',
            'url': get_env('ES_URL', ''),
            'api_key': get_env('ES_API_KEY'),
            'username': get_env('ES_USERNAME'),
            'password': get_env('ES_PASSWORD'),
            'index': get_env('ES_INDEX', 'logs'),  # Changed
            'verify_certs': get_env('ES_VERIFY_CERTS', True, bool),
            'ca_certs': get_env('ES_CA_CERTS'),
            'batch_size': get_env('ES_BATCH_SIZE', 100, int),
            'flush_interval': get_env('ES_FLUSH_INTERVAL', 5.0, float),
        }

    # Load target-specific config
    prefix = f'ES_{target.upper()}_'

    url = os.getenv(f'{prefix}URL', '')

    config = {
        'enabled': bool(url),
        'target': target,
        'url': url,
        'api_key': os.getenv(f'{prefix}API_KEY'),
        'username': os.getenv(f'{prefix}USERNAME'),
        'password': os.getenv(f'{prefix}PASSWORD'),
        'index': os.getenv(f'{prefix}INDEX', 'logs'),  # Changed to INDEX
        'verify_certs': get_env(f'{prefix}VERIFY_CERTS', True, bool),
        'ca_certs': os.getenv(f'{prefix}CA_CERTS'),
        'batch_size': get_env(f'{prefix}BATCH_SIZE', 100, int),
        'flush_interval': get_env(f'{prefix}FLUSH_INTERVAL', 5.0, float),
    }

    if config['url']:
        print(f"✓ ES Target: {target.upper()} -> {config['url']} -> index: {config['index']}")

    return config


def load_config(config_path: str = "config.yaml") -> AppConfig:
    """Load configuration from environment and optional YAML."""

    config = _get_defaults()

    # Load YAML if exists
    if os.path.exists(config_path):
        config = _load_yaml_config(config_path, config)

    # Override with environment
    config = _load_env_config(config)

    # Load ES target configuration
    es_config = _load_es_target_config()
    config['elasticsearch'].update(es_config)

    return AppConfig(
        generator=GeneratorConfig(**config['generator']),
        output=OutputConfig(**config['output']),
        elasticsearch=ElasticsearchConfig(**config['elasticsearch']),
        message_profiles=config['message_profiles'],
        severity_distribution=config['severity_distribution'],
        hosts=config['hosts']
    )


def _get_defaults() -> dict:
    """Get default configuration values."""
    return {
        'generator': {
            'rate': 10.0,
            'max_messages': 0,
            'duration': 0,
            'burst_mode': False,
            'scenario': None
        },
        'output': {
            'mode': 'console',
            'syslog_host': '127.0.0.1',
            'syslog_port': 514,
            'file_path': './logs/syslog_output.log',
            'file_rotation': True,
            'max_file_size_mb': 100
        },
        'elasticsearch': {
            'enabled': False,
            'target': '',
            'url': '',
            'api_key': None,
            'username': None,
            'password': None,
            'index': 'logs',  # Changed
            'verify_certs': True,
            'ca_certs': None,
            'batch_size': 100,
            'flush_interval': 5.0
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
        'hosts': [
            'web-server-01', 'web-server-02', 'db-master-01',
            'app-server-01', 'cache-server-01', 'lb-01'
        ]
    }


def _load_yaml_config(config_path: str, config: dict) -> dict:
    """Load and merge YAML configuration."""
    try:
        with open(config_path, 'r') as f:
            file_config = yaml.safe_load(f) or {}

        for section in config:
            if section in file_config:
                if isinstance(config[section], dict) and isinstance(file_config[section], dict):
                    config[section].update(file_config[section])
                else:
                    config[section] = file_config[section]

    except Exception as e:
        print(f"⚠ Error loading {config_path}: {e}")

    return config


def _load_env_config(config: dict) -> dict:
    """Load non-ES configuration from environment variables."""

    # Generator
    config['generator']['rate'] = get_env('SYSLOG_RATE', config['generator']['rate'], float)
    config['generator']['max_messages'] = get_env('SYSLOG_MAX_MESSAGES', config['generator']['max_messages'], int)
    config['generator']['duration'] = get_env('SYSLOG_DURATION', config['generator']['duration'], int)
    config['generator']['burst_mode'] = get_env('SYSLOG_BURST_MODE', config['generator']['burst_mode'], bool)
    config['generator']['scenario'] = get_env('SYSLOG_SCENARIO', config['generator']['scenario'])

    # Output
    config['output']['mode'] = get_env('SYSLOG_OUTPUT_MODE', config['output']['mode'])
    config['output']['syslog_host'] = get_env('SYSLOG_HOST', config['output']['syslog_host'])
    config['output']['syslog_port'] = get_env('SYSLOG_PORT', config['output']['syslog_port'], int)
    config['output']['file_path'] = get_env('SYSLOG_FILE_PATH', config['output']['file_path'])

    return config
