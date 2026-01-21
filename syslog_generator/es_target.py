#!/usr/bin/env python3
# es_targets.py
"""Programmatic Elasticsearch target management."""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, NamedTuple
from dataclasses import dataclass

try:
    from dotenv import dotenv_values, set_key
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False


@dataclass
class ESTarget:
    """Elasticsearch target configuration."""
    name: str
    url: str
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    index_prefix: str = "syslog-generator"
    verify_certs: bool = True
    ca_certs: Optional[str] = None
    batch_size: int = 100
    flush_interval: float = 5.0

    @property
    def is_valid(self) -> bool:
        """Check if target has required configuration."""
        if not self.url:
            return False
        return bool(self.api_key or (self.username and self.password))

    @property
    def auth_method(self) -> str:
        """Get authentication method."""
        if self.api_key:
            return "api_key"
        elif self.username and self.password:
            return "basic"
        return "none"

    def to_env_vars(self) -> Dict[str, str]:
        """Convert to environment variable dictionary."""
        prefix = f"ES_{self.name.upper()}_"
        env_vars = {
            f"{prefix}URL": self.url,
            f"{prefix}INDEX_PREFIX": self.index_prefix,
            f"{prefix}VERIFY_CERTS": str(self.verify_certs).lower(),
            f"{prefix}BATCH_SIZE": str(self.batch_size),
            f"{prefix}FLUSH_INTERVAL": str(self.flush_interval),
        }

        if self.api_key:
            env_vars[f"{prefix}API_KEY"] = self.api_key
        if self.username:
            env_vars[f"{prefix}USERNAME"] = self.username
        if self.password:
            env_vars[f"{prefix}PASSWORD"] = self.password
        if self.ca_certs:
            env_vars[f"{prefix}CA_CERTS"] = self.ca_certs

        return env_vars


class ESTargetManager:
    """Manage multiple Elasticsearch targets."""

    def __init__(self, env_file: str = ".env"):
        self.env_file = Path(env_file)
        self._targets: Dict[str, ESTarget] = {}
        self._current: Optional[str] = None
        self.load()

    def load(self) -> None:
        """Load targets from environment file."""
        if not self.env_file.exists():
            return

        if DOTENV_AVAILABLE:
            env_vars = dotenv_values(self.env_file)
        else:
            env_vars = self._parse_env_file()

        self._current = env_vars.get('ES_TARGET', '').lower() or None
        self._targets = self._discover_targets(env_vars)

    def _parse_env_file(self) -> Dict[str, str]:
        """Manually parse .env file."""
        env_vars = {}
        with open(self.env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key.strip()] = value.strip().strip('"\'')
        return env_vars

    def _discover_targets(self, env_vars: Dict[str, str]) -> Dict[str, ESTarget]:
        """Discover all targets from environment variables."""
        targets = {}
        pattern = re.compile(r'^ES_([A-Z]+)_URL$')

        for key in env_vars:
            match = pattern.match(key)
            if match:
                name = match.group(1).lower()
                prefix = f'ES_{name.upper()}_'

                targets[name] = ESTarget(
                    name=name,
                    url=env_vars.get(f'{prefix}URL', ''),
                    api_key=env_vars.get(f'{prefix}API_KEY'),
                    username=env_vars.get(f'{prefix}USERNAME'),
                    password=env_vars.get(f'{prefix}PASSWORD'),
                    index_prefix=env_vars.get(f'{prefix}INDEX_PREFIX', f'syslog-{name}'),
                    verify_certs=env_vars.get(f'{prefix}VERIFY_CERTS', 'true').lower() == 'true',
                    ca_certs=env_vars.get(f'{prefix}CA_CERTS'),
                    batch_size=int(env_vars.get(f'{prefix}BATCH_SIZE', 100)),
                    flush_interval=float(env_vars.get(f'{prefix}FLUSH_INTERVAL', 5.0)),
                )

        return targets

    @property
    def current(self) -> Optional[str]:
        """Get current target name."""
        return self._current

    @property
    def current_target(self) -> Optional[ESTarget]:
        """Get current target configuration."""
        if self._current and self._current in self._targets:
            return self._targets[self._current]
        return None

    @property
    def targets(self) -> Dict[str, ESTarget]:
        """Get all targets."""
        return self._targets.copy()

    @property
    def target_names(self) -> List[str]:
        """Get list of target names."""
        return list(self._targets.keys())

    def get(self, name: str) -> Optional[ESTarget]:
        """Get target by name."""
        return self._targets.get(name.lower())

    def switch(self, name: str) -> bool:
        """Switch to a different target."""
        name = name.lower()

        if name not in self._targets:
            raise ValueError(f"Unknown target: {name}")

        if not self.env_file.exists():
            raise FileNotFoundError(f"Environment file not found: {self.env_file}")

        if DOTENV_AVAILABLE:
            set_key(str(self.env_file), 'ES_TARGET', name)
        else:
            self._update_env_file('ES_TARGET', name)

        self._current = name

        # Also update os.environ for current session
        os.environ['ES_TARGET'] = name

        return True

    def _update_env_file(self, key: str, value: str) -> None:
        """Update a key in the env file (fallback method)."""
        lines = self.env_file.read_text().splitlines()
        updated = False
        new_lines = []

        for line in lines:
            if line.strip().startswith(f'{key}='):
                new_lines.append(f'{key}={value}')
                updated = True
            else:
                new_lines.append(line)

        if not updated:
            new_lines.insert(0, f'{key}={value}')

        self.env_file.write_text('\n'.join(new_lines) + '\n')

    def add_target(self, target: ESTarget) -> None:
        """Add a new target to the env file."""
        if not DOTENV_AVAILABLE:
            raise RuntimeError("python-dotenv required to add targets")

        for key, value in target.to_env_vars().items():
            if value:
                set_key(str(self.env_file), key, value)

        self._targets[target.name] = target

    def remove_target(self, name: str) -> bool:
        """Remove a target from configuration."""
        name = name.lower()

        if name not in self._targets:
            return False

        # Read file and remove matching lines
        if self.env_file.exists():
            prefix = f'ES_{name.upper()}_'
            lines = self.env_file.read_text().splitlines()
            new_lines = [l for l in lines if not l.strip().startswith(prefix)]
            self.env_file.write_text('\n'.join(new_lines) + '\n')

        del self._targets[name]

        if self._current == name:
            self._current = None

        return True

    def test_connection(self, name: str = None) -> tuple[bool, str]:
        """Test connection to a target.

        Returns:
            Tuple of (success, message)
        """
        target = self.get(name) if name else self.current_target

        if not target:
            return False, "No target specified"

        if not target.is_valid:
            return False, "Target configuration incomplete"

        try:
            from elasticsearch import Elasticsearch

            es_kwargs = {
                'hosts': [target.url],
                'verify_certs': target.verify_certs
            }

            if target.api_key:
                es_kwargs['api_key'] = target.api_key
            elif target.username and target.password:
                es_kwargs['basic_auth'] = (target.username, target.password)

            if target.ca_certs:
                es_kwargs['ca_certs'] = target.ca_certs

            es = Elasticsearch(**es_kwargs)
            info = es.info()
            es.close()

            return True, f"Connected to {info['cluster_name']} (v{info['version']['number']})"

        except ImportError:
            return False, "elasticsearch package not installed"
        except Exception as e:
            return False, str(e)

    def print_status(self) -> None:
        """Print current status."""
        print("\n" + "="*50)
        print("  ELASTICSEARCH TARGETS")
        print("="*50)

        if not self._targets:
            print("  No targets configured")
            print("="*50 + "\n")
            return

        for name, target in sorted(self._targets.items()):
            is_current = name == self._current
            prefix = "▶ " if is_current else "  "
            status = "ACTIVE" if is_current else ("Ready" if target.is_valid else "Invalid")

            print(f"\n{prefix}{name.upper()} [{status}]")
            print(f"    URL:    {target.url}")
            print(f"    Auth:   {target.auth_method}")
            print(f"    Index:  {target.index_prefix}-*")

        print("\n" + "="*50 + "\n")


# Convenience functions
_manager: Optional[ESTargetManager] = None

def get_manager(env_file: str = ".env") -> ESTargetManager:
    """Get or create the global target manager."""
    global _manager
    if _manager is None or str(_manager.env_file) != env_file:
        _manager = ESTargetManager(env_file)
    return _manager


def switch(target: str, env_file: str = ".env") -> bool:
    """Quick switch to target."""
    return get_manager(env_file).switch(target)


def current(env_file: str = ".env") -> Optional[str]:
    """Get current target name."""
    return get_manager(env_file).current


def targets(env_file: str = ".env") -> List[str]:
    """Get list of available targets."""
    return get_manager(env_file).target_names


# CLI
if __name__ == '__main__':
    import sys

    manager = ESTargetManager()

    if len(sys.argv) < 2:
        manager.print_status()
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd == 'list':
        manager.print_status()
    elif cmd == 'current':
        print(manager.current or "none")
    elif cmd == 'switch' and len(sys.argv) > 2:
        try:
            manager.switch(sys.argv[2])
            print(f"Switched to: {sys.argv[2]}")
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
    elif cmd == 'test':
        target = sys.argv[2] if len(sys.argv) > 2 else None
        success, msg = manager.test_connection(target)
        print(msg)
        sys.exit(0 if success else 1)
    else:
        # Assume it's a target name
        try:
            manager.switch(cmd)
            print(f"Switched to: {cmd}")
        except ValueError:
            print(f"Unknown command or target: {cmd}")
            sys.exit(1)
