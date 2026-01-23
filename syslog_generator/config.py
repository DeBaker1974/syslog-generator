"""Configuration management for syslog generator."""

import os
import re
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

# Try to load .env file
try:
    from dotenv import load_dotenv
    env_path = Path('.env')
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass


@dataclass
class ESTargetConfig:
    """Elasticsearch target configuration."""
    name: str
    url: str
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    index: Optional[str] = None          # Full index name (overrides dataset/namespace)
    dataset: str = "syslog"              # For logs-<dataset>-<namespace>
    namespace: str = "default"           # For logs-<dataset>-<namespace>
    batch_size: int = 100
    verify_certs: bool = True

    @property
    def data_stream_name(self) -> str:
        """Get the full data stream name."""
        if self.index:
            return self.index.lower()
        return f"logs-{self.dataset}-{self.namespace}".lower()

    def __post_init__(self):
        """Validate configuration."""
        if not self.api_key and not (self.username and self.password):
            raise ValueError(f"Target '{self.name}' requires api_key or username/password")


@dataclass
class OutputConfig:
    """Output configuration."""
    mode: str = "console"  # console, udp, tcp, file, all, none
    syslog_host: str = "localhost"
    syslog_port: int = 514
    file_path: str = "./syslog.log"


@dataclass
class GeneratorConfig:
    """Generator configuration."""
    rate: float = 10.0
    max_messages: Optional[int] = None
    duration: Optional[int] = None


@dataclass
class Config:
    """Main configuration."""
    # Generator settings
    generator: GeneratorConfig = field(default_factory=GeneratorConfig)
    output: OutputConfig = field(default_factory=OutputConfig)

    # Elasticsearch
    es_enabled: bool = True
    es_target: Optional[ESTargetConfig] = None

    # Runtime - set by main.py
    es_client: Any = None

    # Logging
    log_level: str = "INFO"
    verbose: bool = False


def discover_es_targets() -> Dict[str, Dict[str, Any]]:
    """Discover all ES targets from environment variables.

    Pattern: ES_<TARGET>_<SETTING>

    Examples:
        ES_PROD_URL=https://...
        ES_PROD_API_KEY=xxx
        ES_PROD_DATASET=syslog
        ES_PROD_NAMESPACE=prod
    """
    targets = {}

    # Pattern: ES_<TARGET>_<SETTING>
    pattern = re.compile(
        r'^ES_([A-Z][A-Z0-9_]*)_(URL|API_KEY|USERNAME|PASSWORD|INDEX|DATASET|NAMESPACE|BATCH_SIZE|VERIFY_CERTS)$'
    )

    for key, value in os.environ.items():
        match = pattern.match(key)
        if match:
            target_name = match.group(1).lower()
            setting = match.group(2).lower()

            # Skip ES_TARGET itself
            if target_name == 'target':
                continue

            if target_name not in targets:
                targets[target_name] = {'name': target_name}

            # Type conversion
            if setting == 'batch_size':
                value = int(value)
            elif setting == 'verify_certs':
                value = value.lower() not in ('false', '0', 'no')

            targets[target_name][setting] = value

    return targets


def get_active_es_target() -> Optional[ESTargetConfig]:
    """Get the currently active ES target configuration."""
    # Check if ES is disabled
    es_enabled = os.getenv('ES_ENABLED', 'true').lower() not in ('false', '0', 'no')
    if not es_enabled:
        return None

    target_name = os.getenv('ES_TARGET', '').lower().strip('"\'')

    if not target_name:
        logger.debug("No ES_TARGET set")
        return None

    targets = discover_es_targets()

    if target_name not in targets:
        available = ', '.join(targets.keys()) if targets else 'none'
        logger.warning(f"ES_TARGET '{target_name}' not found. Available: {available}")
        return None

    target_config = targets[target_name]

    try:
        config = ESTargetConfig(**target_config)
        logger.info(f"✓ ES Target: {target_name.upper()} -> {config.url} -> {config.data_stream_name}")
        return config
    except Exception as e:
        logger.error(f"Invalid target config '{target_name}': {e}")
        return None


def load_config(config_path: str = "config.yaml") -> Config:
    """Load configuration from YAML file and environment.

    Priority (highest to lowest):
        1. Command line arguments (handled in main.py)
        2. Environment variables
        3. YAML config file
        4. Defaults
    """
    config = Config()

    # Load from YAML if exists
    yaml_path = Path(config_path)
    if yaml_path.exists():
        try:
            with open(yaml_path, 'r') as f:
                yaml_config = yaml.safe_load(f) or {}

            # Apply YAML config
            if 'generator' in yaml_config:
                gen = yaml_config['generator']
                config.generator.rate = gen.get('rate', config.generator.rate)
                config.generator.max_messages = gen.get('max_messages')
                config.generator.duration = gen.get('duration')

            if 'output' in yaml_config:
                out = yaml_config['output']
                config.output.mode = out.get('mode', config.output.mode)
                config.output.syslog_host = out.get('syslog_host', config.output.syslog_host)
                config.output.syslog_port = out.get('syslog_port', config.output.syslog_port)
                config.output.file_path = out.get('file_path', config.output.file_path)

            logger.debug(f"Loaded config from {config_path}")
        except Exception as e:
            logger.warning(f"Could not load {config_path}: {e}")

    # Override with environment variables
    if os.getenv('SYSLOG_RATE'):
        config.generator.rate = float(os.getenv('SYSLOG_RATE'))
    if os.getenv('SYSLOG_MAX_MESSAGES'):
        config.generator.max_messages = int(os.getenv('SYSLOG_MAX_MESSAGES'))
    if os.getenv('SYSLOG_DURATION'):
        config.generator.duration = int(os.getenv('SYSLOG_DURATION'))
    if os.getenv('SYSLOG_OUTPUT_MODE'):
        config.output.mode = os.getenv('SYSLOG_OUTPUT_MODE')

    config.log_level = os.getenv('LOG_LEVEL', 'INFO')
    config.verbose = os.getenv('VERBOSE', '').lower() in ('true', '1', 'yes')

    # Load ES target
    es_target = get_active_es_target()
    if es_target:
        config.es_target = es_target
        config.es_enabled = True
    else:
        config.es_enabled = os.getenv('ES_ENABLED', 'true').lower() not in ('false', '0', 'no')

    return config
