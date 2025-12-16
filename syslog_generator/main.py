# syslog_generator/main.py
"""Main entry point for the syslog generator."""

import argparse
import logging
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from syslog_generator.config import load_config
from syslog_generator.generator import SyslogGenerator, BurstGenerator


def setup_logging(verbose: bool = False) -> None:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Generate realistic syslog messages for testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with default config (console output)
  python -m syslog_generator.main
  
  # Run with custom rate
  python -m syslog_generator.main --rate 100
  
  # Send to syslog server via UDP
  python -m syslog_generator.main --mode udp --host 192.168.1.100 --port 514
  
  # Write to file
  python -m syslog_generator.main --mode file --file ./logs/syslog.log
  
  # Generate specific number of messages
  python -m syslog_generator.main --count 1000 --rate 50
  
  # Run for specific duration
  python -m syslog_generator.main --duration 60 --rate 10
  
  # Burst mode (simulates incidents)
  python -m syslog_generator.main --burst
        """
    )
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '--mode', '-m',
        choices=['console', 'udp', 'tcp', 'file', 'all'],
        default=None,
        help='Output mode (default: from config or console)'
    )
    output_group.add_argument(
        '--host', '-H',
        default=None,
        help='Syslog server host (for udp/tcp modes)'
    )
    output_group.add_argument(
        '--port', '-P',
        type=int,
        default=None,
        help='Syslog server port (for udp/tcp modes)'
    )
# syslog_generator/main.py (continued)

    output_group.add_argument(
        '--file', '-f',
        default=None,
        help='Output file path (for file mode)'
    )
    
    # Generation options
    gen_group = parser.add_argument_group('Generation Options')
    gen_group.add_argument(
        '--rate', '-r',
        type=float,
        default=None,
        help='Messages per second (default: from config or 10)'
    )
    gen_group.add_argument(
        '--count', '-c',
        type=int,
        default=None,
        help='Total messages to generate (0 = unlimited)'
    )
    gen_group.add_argument(
        '--duration', '-d',
        type=int,
        default=None,
        help='Duration in seconds (0 = unlimited)'
    )
    gen_group.add_argument(
        '--burst', '-b',
        action='store_true',
        help='Enable burst mode (simulates incidents)'
    )
    
    # Configuration
    config_group = parser.add_argument_group('Configuration')
    config_group.add_argument(
        '--config',
        default='config.yaml',
        help='Path to configuration file (default: config.yaml)'
    )
    config_group.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    # Quick presets
    preset_group = parser.add_argument_group('Presets')
    preset_group.add_argument(
        '--preset',
        choices=['low', 'medium', 'high', 'stress'],
        default=None,
        help='Use a predefined rate preset'
    )
    
    return parser.parse_args()


def apply_presets(args: argparse.Namespace) -> None:
    """Apply rate presets if specified."""
    presets = {
        'low': 1,        # 1 msg/sec
        'medium': 10,    # 10 msg/sec
        'high': 100,     # 100 msg/sec
        'stress': 1000,  # 1000 msg/sec
    }
    
    if args.preset and args.rate is None:
        args.rate = presets[args.preset]


def main() -> int:
    """Main entry point."""
    args = parse_arguments()
    setup_logging(args.verbose)
    
    # Apply presets
    apply_presets(args)
    
    # Load configuration
    try:
        config = load_config(args.config)
    except Exception as e:
        logging.error(f"Failed to load configuration: {e}")
        return 1
    
    # Override config with command line arguments
    if args.mode:
        config.output.mode = args.mode
    if args.host:
        config.output.syslog_host = args.host
    if args.port:
        config.output.syslog_port = args.port
    if args.file:
        config.output.file_path = args.file
    if args.rate is not None:
        config.generator.rate = args.rate
    if args.count is not None:
        config.generator.max_messages = args.count
    if args.duration is not None:
        config.generator.duration = args.duration
    
    # Create and start generator
    try:
        if args.burst:
            generator = BurstGenerator(config)
        else:
            generator = SyslogGenerator(config)
        
        generator.start()
        return 0
        
    except Exception as e:
        logging.error(f"Generator error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())

