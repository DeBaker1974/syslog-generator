#!/usr/bin/env python3
# switch_target.py
"""Interactive script to switch Elasticsearch targets."""

import os
import sys
import re
from pathlib import Path
from typing import Dict, List, Optional

# Try to load current .env
try:
    from dotenv import dotenv_values, set_key
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False
    print("⚠ python-dotenv not installed. Install with: pip install python-dotenv")


ENV_FILE = Path('.env')

# ANSI colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def load_env_file() -> Dict[str, str]:
    """Load environment variables from .env file."""
    if not ENV_FILE.exists():
        return {}

    if DOTENV_AVAILABLE:
        return dotenv_values(ENV_FILE)

    # Fallback: manual parsing
    env_vars = {}
    with open(ENV_FILE, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                env_vars[key.strip()] = value.strip().strip('"\'')
    return env_vars


def discover_targets(env_vars: Dict[str, str]) -> Dict[str, Dict[str, str]]:
    """Discover all ES targets from environment variables."""
    targets = {}
    # Pattern: ES_<TARGET>_<SETTING>
    # Added DATASET and NAMESPACE for data streams
    pattern = re.compile(
        r'^ES_([A-Z]+)_(URL|API_KEY|USERNAME|PASSWORD|INDEX|INDEX_PREFIX|'
        r'DATASET|NAMESPACE|VERIFY_CERTS|CA_CERTS|BATCH_SIZE|FLUSH_INTERVAL)$'
    )
    for key, value in env_vars.items():
        match = pattern.match(key)
        if match:
            target_name = match.group(1).lower()
            setting = match.group(2).lower()
            if target_name not in targets:
                targets[target_name] = {}
            targets[target_name][setting] = value
    return targets

def get_current_target(env_vars: Dict[str, str]) -> str:
    """Get currently active target."""
    # Strip quotes in case they're present
    target = env_vars.get('ES_TARGET', 'none').lower()
    return target.strip('"\'')


def validate_target(target: Dict[str, str]) -> tuple[bool, List[str]]:
    """Validate target configuration."""
    issues = []

    if not target.get('url'):
        issues.append("Missing URL")

    has_api_key = bool(target.get('api_key'))
    has_basic_auth = bool(target.get('username') and target.get('password'))

    if not has_api_key and not has_basic_auth:
        issues.append("Missing authentication (need API key or username/password)")

    return len(issues) == 0, issues


def get_index_display(config: Dict[str, str]) -> str:
    """Get the index display string for a target."""
    # Check for direct index name first
    index = config.get('index')
    if index:
        return index
    # Check for dataset/namespace (Elastic data streams)
    dataset = config.get('dataset')
    namespace = config.get('namespace')
    if dataset:
        ns = namespace or 'default'
        return f"logs-{dataset}-{ns}"
    # Fall back to index_prefix with date pattern
    prefix = config.get('index_prefix')
    if prefix:
        return f"{prefix}-YYYY.MM.DD"
    # Default
    return "syslog-generator-YYYY.MM.DD"
    """Get the index display string for a target."""
    # Check for direct index name first (e.g., "logs")
    index = config.get('index')
    if index:
        return index

    # Fall back to index_prefix with date pattern
    prefix = config.get('index_prefix')
    if prefix:
        return f"{prefix}-YYYY.MM.DD"

    # Default
    return "syslog-generator-YYYY.MM.DD"


def print_targets(targets: Dict[str, Dict[str, str]], current: str) -> None:
    """Print all available targets."""
    print(f"\n{Colors.HEADER}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  ELASTICSEARCH TARGETS{Colors.RESET}")
    print(f"{Colors.HEADER}{'='*60}{Colors.RESET}\n")

    if not targets:
        print(f"  {Colors.YELLOW}No targets configured in .env file{Colors.RESET}")
        print(f"  Add targets with ES_<NAME>_URL, ES_<NAME>_API_KEY, etc.\n")
        return

    for name, config in sorted(targets.items()):
        is_current = name == current
        is_valid, issues = validate_target(config)

        # Status indicator
        if is_current:
            indicator = f"{Colors.GREEN}▶ ACTIVE{Colors.RESET}"
        elif is_valid:
            indicator = f"{Colors.CYAN}  Ready{Colors.RESET}"
        else:
            indicator = f"{Colors.RED}  Invalid{Colors.RESET}"

        # Target name
        name_display = f"{Colors.BOLD}{name.upper()}{Colors.RESET}"
        if is_current:
            name_display = f"{Colors.GREEN}{Colors.BOLD}{name.upper()}{Colors.RESET}"

        print(f"  {indicator}  {name_display}")

        # URL
        url = config.get('url', 'not set')
        print(f"           URL: {url}")

        # Auth method
        if config.get('api_key'):
            print(f"           Auth: API Key (***)")
        elif config.get('username'):
            print(f"           Auth: Basic ({config['username']}/***)")
        else:
            print(f"           Auth: {Colors.RED}Not configured{Colors.RESET}")

        # Index - handles both 'index' and 'index_prefix'
        index_display = get_index_display(config)
        print(f"           Index: {index_display}")

        # Batch size if configured
        batch_size = config.get('batch_size')
        if batch_size:
            print(f"           Batch: {batch_size}")

        # SSL verification
        verify = config.get('verify_certs', 'true')
        if verify.lower() == 'false':
            print(f"           SSL: {Colors.YELLOW}verify_certs=false{Colors.RESET}")

        # Issues
        if issues:
            for issue in issues:
                print(f"           {Colors.RED}⚠ {issue}{Colors.RESET}")

        print()

    print(f"{Colors.HEADER}{'='*60}{Colors.RESET}\n")


def switch_target(new_target: str) -> bool:
    """Switch to a new target."""
    if not DOTENV_AVAILABLE:
        print(f"{Colors.RED}Cannot switch: python-dotenv not installed{Colors.RESET}")
        return False

    if not ENV_FILE.exists():
        print(f"{Colors.RED}Cannot switch: .env file not found{Colors.RESET}")
        return False

    # Update ES_TARGET in .env file (without quotes)
    set_key(str(ENV_FILE), 'ES_TARGET', new_target, quote_mode='never')
    print(f"{Colors.GREEN}✓ Switched to target: {new_target.upper()}{Colors.RESET}")
    return True


def update_target_inline(env_file: Path, new_target: str) -> bool:
    """Update target by modifying file directly (fallback)."""
    if not env_file.exists():
        return False

    lines = env_file.read_text().splitlines()
    updated = False
    new_lines = []

    for line in lines:
        if line.strip().startswith('ES_TARGET='):
            new_lines.append(f'ES_TARGET={new_target}')
            updated = True
        else:
            new_lines.append(line)

    if not updated:
        # Add if not exists
        new_lines.insert(0, f'ES_TARGET={new_target}')

    env_file.write_text('\n'.join(new_lines) + '\n')
    return True


def test_connection(target_name: str, target_config: Dict[str, str]) -> bool:
    """Test connection to target."""
    print(f"\n{Colors.CYAN}Testing connection to {target_name.upper()}...{Colors.RESET}")

    try:
        from elasticsearch import Elasticsearch

        url = target_config.get('url')
        if not url:
            print(f"{Colors.RED}✗ No URL configured{Colors.RESET}")
            return False

        # Build connection
        es_kwargs = {
            'hosts': [url],
            'verify_certs': target_config.get('verify_certs', 'true').lower() != 'false'
        }

        if target_config.get('api_key'):
            es_kwargs['api_key'] = target_config['api_key']
        elif target_config.get('username') and target_config.get('password'):
            es_kwargs['basic_auth'] = (target_config['username'], target_config['password'])

        if target_config.get('ca_certs'):
            es_kwargs['ca_certs'] = target_config['ca_certs']

        es = Elasticsearch(**es_kwargs)
        info = es.info()

        print(f"{Colors.GREEN}✓ Connected successfully!{Colors.RESET}")
        print(f"  Cluster: {info['cluster_name']}")
        print(f"  Version: {info['version']['number']}")

        # Test index access
        index_name = target_config.get('index') or target_config.get('index_prefix', 'syslog-generator')
        print(f"  Target index: {index_name}")

        # Check if index exists and get doc count
        try:
            if es.indices.exists(index=index_name):
                count = es.count(index=index_name)['count']
                print(f"  {Colors.GREEN}Index exists: {count:,} documents{Colors.RESET}")
            else:
                print(f"  {Colors.YELLOW}Index does not exist yet (will be created on first write){Colors.RESET}")
        except Exception as e:
            print(f"  {Colors.YELLOW}Could not check index: {e}{Colors.RESET}")

        es.close()
        return True

    except ImportError:
        print(f"{Colors.YELLOW}⚠ elasticsearch package not installed{Colors.RESET}")
        return False
    except Exception as e:
        print(f"{Colors.RED}✗ Connection failed: {e}{Colors.RESET}")
        return False


def show_index_contents(target_name: str, target_config: Dict[str, str], count: int = 5) -> None:
    """Show recent documents from the target index."""
    print(f"\n{Colors.CYAN}Recent documents from {target_name.upper()}...{Colors.RESET}")

    try:
        from elasticsearch import Elasticsearch

        url = target_config.get('url')
        if not url:
            print(f"{Colors.RED}✗ No URL configured{Colors.RESET}")
            return

        # Build connection
        es_kwargs = {
            'hosts': [url],
            'verify_certs': target_config.get('verify_certs', 'true').lower() != 'false'
        }

        if target_config.get('api_key'):
            es_kwargs['api_key'] = target_config['api_key']
        elif target_config.get('username') and target_config.get('password'):
            es_kwargs['basic_auth'] = (target_config['username'], target_config['password'])

        es = Elasticsearch(**es_kwargs)

        index_name = target_config.get('index') or target_config.get('index_prefix', 'syslog-generator')

        # Search for recent docs
        result = es.search(
            index=index_name,
            body={
                "size": count,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "_source": ["@timestamp", "message", "host.name", "process.name", "log.level"]
            }
        )

        hits = result['hits']['hits']
        if not hits:
            print(f"  {Colors.YELLOW}No documents found{Colors.RESET}")
        else:
            print(f"  Found {result['hits']['total']['value']:,} total documents\n")
            for hit in hits:
                src = hit['_source']
                ts = src.get('@timestamp', 'N/A')[:19]
                msg = src.get('message', 'N/A')[:60]
                host = src.get('host', {}).get('name', 'N/A')
                level = src.get('log', {}).get('level', 'N/A')
                print(f"  {Colors.CYAN}{ts}{Colors.RESET} [{level}] {host}: {msg}...")

        es.close()

    except Exception as e:
        print(f"{Colors.RED}✗ Error: {e}{Colors.RESET}")


def interactive_menu(targets: Dict[str, Dict[str, str]], current: str) -> None:
    """Run interactive target selection menu."""
    while True:
        print_targets(targets, current)

        print("Commands:")
        print(f"  {Colors.CYAN}<name>{Colors.RESET}    - Switch to target (e.g., 'prod', 'dev')")
        print(f"  {Colors.CYAN}test{Colors.RESET}      - Test current target connection")
        print(f"  {Colors.CYAN}test <name>{Colors.RESET} - Test specific target")
        print(f"  {Colors.CYAN}show{Colors.RESET}      - Show recent docs from current target")
        print(f"  {Colors.CYAN}show <name>{Colors.RESET} - Show recent docs from specific target")
        print(f"  {Colors.CYAN}list{Colors.RESET}      - Refresh target list")
        print(f"  {Colors.CYAN}q/quit{Colors.RESET}    - Exit")
        print()

        try:
            cmd = input(f"{Colors.BOLD}Enter command: {Colors.RESET}").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\n")
            break

        if not cmd:
            continue

        if cmd in ('q', 'quit', 'exit'):
            break

        if cmd == 'list':
            env_vars = load_env_file()
            targets = discover_targets(env_vars)
            current = get_current_target(env_vars)
            continue

        if cmd == 'test':
            if current in targets:
                test_connection(current, targets[current])
            else:
                print(f"{Colors.YELLOW}No active target to test{Colors.RESET}")
            input("\nPress Enter to continue...")
            continue

        if cmd.startswith('test '):
            target_name = cmd.split(' ', 1)[1]
            if target_name in targets:
                test_connection(target_name, targets[target_name])
            else:
                print(f"{Colors.RED}Unknown target: {target_name}{Colors.RESET}")
            input("\nPress Enter to continue...")
            continue

        if cmd == 'show':
            if current in targets:
                show_index_contents(current, targets[current])
            else:
                print(f"{Colors.YELLOW}No active target{Colors.RESET}")
            input("\nPress Enter to continue...")
            continue

        if cmd.startswith('show '):
            target_name = cmd.split(' ', 1)[1]
            if target_name in targets:
                show_index_contents(target_name, targets[target_name])
            else:
                print(f"{Colors.RED}Unknown target: {target_name}{Colors.RESET}")
            input("\nPress Enter to continue...")
            continue

        # Try to switch target
        if cmd in targets:
            is_valid, issues = validate_target(targets[cmd])
            if not is_valid:
                print(f"{Colors.YELLOW}⚠ Target has issues: {', '.join(issues)}{Colors.RESET}")
                confirm = input("Switch anyway? [y/N]: ").strip().lower()
                if confirm != 'y':
                    continue

            if switch_target(cmd):
                current = cmd
                # Offer to test
                test_now = input("Test connection now? [Y/n]: ").strip().lower()
                if test_now != 'n':
                    test_connection(cmd, targets[cmd])
                    input("\nPress Enter to continue...")
        else:
            print(f"{Colors.RED}Unknown target: {cmd}{Colors.RESET}")
            print(f"Available: {', '.join(targets.keys())}")


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Switch Elasticsearch targets',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python switch_target.py              # Interactive mode
  python switch_target.py --list       # List all targets
  python switch_target.py --switch prod  # Switch to prod
  python switch_target.py --test       # Test current target
  python switch_target.py --test staging # Test specific target
  python switch_target.py --show       # Show recent docs from current target
  python switch_target.py --show prod  # Show recent docs from prod
        """
    )

    parser.add_argument('--list', '-l', action='store_true',
                        help='List all targets')
    parser.add_argument('--switch', '-s', metavar='TARGET',
                        help='Switch to specified target')
    parser.add_argument('--test', '-t', nargs='?', const='__current__', metavar='TARGET',
                        help='Test connection (current target if not specified)')
    parser.add_argument('--show', nargs='?', const='__current__', metavar='TARGET',
                        help='Show recent documents (current target if not specified)')
    parser.add_argument('--current', '-c', action='store_true',
                        help='Show current target')
    parser.add_argument('--env-file', '-e', default='.env',
                        help='Path to .env file (default: .env)')

    args = parser.parse_args()

    global ENV_FILE
    ENV_FILE = Path(args.env_file)

    # Load environment
    env_vars = load_env_file()
    targets = discover_targets(env_vars)
    current = get_current_target(env_vars)

    # Handle commands
    if args.current:
        if current and current in targets:
            print(f"{current.upper()}")
            url = targets[current].get('url', 'not set')
            index = get_index_display(targets[current])
            print(f"URL: {url}")
            print(f"Index: {index}")
        else:
            print("none")
        sys.exit(0)

    if args.list:
        print_targets(targets, current)
        sys.exit(0)

    if args.switch:
        target = args.switch.lower()
        if target not in targets:
            print(f"{Colors.RED}Unknown target: {target}{Colors.RESET}")
            print(f"Available: {', '.join(targets.keys())}")
            sys.exit(1)

        if switch_target(target):
            sys.exit(0)
        sys.exit(1)

    if args.test:
        if args.test == '__current__':
            # Test current
            if current and current in targets:
                success = test_connection(current, targets[current])
                sys.exit(0 if success else 1)
            else:
                print(f"{Colors.RED}No active target{Colors.RESET}")
                sys.exit(1)
        else:
            # Test specific target
            target = args.test.lower()
            if target in targets:
                success = test_connection(target, targets[target])
                sys.exit(0 if success else 1)
            else:
                print(f"{Colors.RED}Unknown target: {target}{Colors.RESET}")
                sys.exit(1)

    if args.show:
        if args.show == '__current__':
            if current and current in targets:
                show_index_contents(current, targets[current])
                sys.exit(0)
            else:
                print(f"{Colors.RED}No active target{Colors.RESET}")
                sys.exit(1)
        else:
            target = args.show.lower()
            if target in targets:
                show_index_contents(target, targets[target])
                sys.exit(0)
            else:
                print(f"{Colors.RED}Unknown target: {target}{Colors.RESET}")
                sys.exit(1)

    # Default: interactive mode
    if not targets:
        print(f"{Colors.YELLOW}No targets found in {ENV_FILE}{Colors.RESET}")
        print("Configure targets with ES_<NAME>_URL, ES_<NAME>_API_KEY, etc.")
        sys.exit(1)

    interactive_menu(targets, current)


if __name__ == '__main__':
    main()
