"""Main entry point for the syslog generator."""

import argparse
import logging
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from syslog_generator.config import load_config


logger = logging.getLogger(__name__)


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
  # Run with default config (uses ES_TARGET from .env)
  python -m syslog_generator.main

  # Run with custom rate
  python -m syslog_generator.main --rate 100

  # Switch ES target (overrides .env)
  python -m syslog_generator.main --es-target staging
  python -m syslog_generator.main --es-target dev

  # Disable ES output (console only)
  python -m syslog_generator.main --no-es

  # Send to ES only (no console output)
  python -m syslog_generator.main --es-only

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

  # Specify data stream components
  python -m syslog_generator.main --dataset nginx --namespace prod
        """
    )

    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '--mode', '-m',
        choices=['console', 'udp', 'tcp', 'file', 'all', 'none'],
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
    output_group.add_argument(
        '--file', '-f',
        default=None,
        help='Output file path (for file mode)'
    )

    # Elasticsearch options (uses .env multi-target config)
    es_group = parser.add_argument_group('Elasticsearch Options')
    es_group.add_argument(
        '--es-target',
        default=None,
        help='ES target environment (overrides ES_TARGET in .env). Examples: dev, staging, prod'
    )
    es_group.add_argument(
        '--no-es',
        action='store_true',
        help='Disable Elasticsearch output'
    )
    es_group.add_argument(
        '--es-only',
        action='store_true',
        help='Send to Elasticsearch only (disable console/syslog output)'
    )

    # Data stream options
    ds_group = parser.add_argument_group('Data Stream Options (logs-<dataset>-<namespace>)')
    ds_group.add_argument(
        '--dataset',
        default=None,
        help='Data stream dataset (e.g., syslog, nginx, myapp)'
    )
    ds_group.add_argument(
        '--namespace',
        default=None,
        help='Data stream namespace (e.g., default, prod, dev)'
    )
    ds_group.add_argument(
        '--index',
        default=None,
        help='Full index/data stream name (overrides dataset/namespace)'
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


def init_elasticsearch(config, args):
    """Initialize Elasticsearch client from config.

    Args:
        config: Loaded configuration object with es_target settings
        args: Parsed command line arguments

    Returns:
        ESClient instance or None
    """
    # Check if ES is enabled
    if not config.es_enabled:
        logger.info("Elasticsearch output disabled")
        return None

    # Get ES target config
    es_target = config.es_target
    if not es_target:
        logger.warning("No Elasticsearch target configured")
        return None

    # Command line overrides for data stream components
    dataset = args.dataset if args.dataset else es_target.dataset
    namespace = args.namespace if args.namespace else es_target.namespace
    index = args.index if args.index else es_target.index

    try:
        from syslog_generator.es_client import ESClient

        es_client = ESClient(
            url=es_target.url,
            api_key=es_target.api_key,
            username=es_target.username,
            password=es_target.password,
            index=index,
            dataset=dataset,
            namespace=namespace,
            buffer_size=es_target.batch_size,
            verify_certs=es_target.verify_certs
        )

        logger.info(f"✓ Elasticsearch [{es_target.name.upper()}] -> {es_target.url}")
        logger.info(f"  Data stream: {es_client.index}")
        logger.info(f"  Dataset: {es_client.dataset}, Namespace: {es_client.namespace}")
        logger.info(f"  Batch size: {es_target.batch_size}")
        return es_client

    except ImportError:
        logger.error("elasticsearch package not installed. Run: pip install elasticsearch")
        return None
    except Exception as e:
        logger.error(f"✗ Failed to connect to Elasticsearch: {e}")
        if logger.level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        return None


def main() -> int:
    """Main entry point."""
    args = parse_arguments()
    setup_logging(args.verbose)

    # Apply presets
    apply_presets(args)

    # Override ES_TARGET from command line if specified
    if args.es_target:
        os.environ['ES_TARGET'] = args.es_target
        logger.info(f"ES target overridden to: {args.es_target}")

    # Handle --no-es flag
    if args.no_es:
        os.environ['ES_ENABLED'] = 'false'

    # Load configuration (reads .env and resolves ES target)
    try:
        config = load_config(args.config)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    # Initialize Elasticsearch client from config
    es_client = None
    if not args.no_es:
        es_client = init_elasticsearch(config, args)

    # Check if --es-only was requested but ES failed
    if args.es_only and not es_client:
        logger.error("--es-only requires working Elasticsearch connection")
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

    # If es-only mode, disable other outputs
    if args.es_only:
        config.output.mode = 'none'

    # Attach ES client to config so generator can use it
    config.es_client = es_client

    # Log startup summary
    logger.info("=" * 50)
    logger.info("Syslog Generator Starting")
    logger.info(f"  Output mode: {config.output.mode}")
    logger.info(f"  Rate: {config.generator.rate} msg/sec")
    if config.generator.max_messages:
        logger.info(f"  Max messages: {config.generator.max_messages}")
    if config.generator.duration:
        logger.info(f"  Duration: {config.generator.duration}s")
    logger.info(f"  Elasticsearch: {'enabled' if es_client else 'disabled'}")
    logger.info("=" * 50)

    # Create and start generator
    try:
        from syslog_generator.generator import SyslogGenerator, BurstGenerator

        if args.burst:
            generator = BurstGenerator(config)
        else:
            generator = SyslogGenerator(config)

        generator.start()
        return 0

    except KeyboardInterrupt:
        logger.info("\nInterrupted by user")
        return 0
    except Exception as e:
        logger.error(f"Generator error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    finally:
        # Ensure ES client is properly closed
        if es_client:
            es_client.close()


if __name__ == '__main__':
    sys.exit(main())
