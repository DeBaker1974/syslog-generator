"""Syslog message generator with multiple output options."""

import logging
import random
import socket
import time
from datetime import datetime, timezone
from typing import Optional, List

from .templates import MessageTemplates, SEVERITIES, FACILITIES

logger = logging.getLogger(__name__)


class SyslogGenerator:
    """Generate and send syslog messages using templates."""

    # Sample hostnames
    HOSTNAMES = [
        'web-server-01', 'web-server-02', 'db-master-01', 'db-replica-01',
        'app-server-01', 'app-server-02', 'cache-server-01', 'lb-01',
        'monitoring-01', 'backup-server-01', 'mail-server-01', 'dns-01',
        'k8s-node-01', 'k8s-node-02', 'k8s-master-01', 'gateway-01'
    ]

    # Message categories with weights for realistic distribution
    CATEGORY_WEIGHTS = {
        'auth': 15,
        'network': 10,
        'application': 25,
        'system': 15,
        'security': 10,
        'database': 10,
        'web_server': 15
    }

    # Severity weights for realistic distribution
    SEVERITY_WEIGHTS = {
        'debug': 5,
        'info': 50,
        'notice': 15,
        'warning': 15,
        'error': 10,
        'critical': 3,
        'alert': 1,
        'emergency': 1
    }

    def __init__(self, config):
        """Initialize the generator.

        Args:
            config: Configuration object with generator and output settings
        """
        self.config = config
        self.running = False
        self.message_count = 0
        self.start_time = None

        # Template generator
        self.templates = MessageTemplates()

        # Network sockets
        self._udp_socket = None
        self._tcp_socket = None
        self._file_handle = None

        # Initialize outputs
        self._init_outputs()

    def _init_outputs(self) -> None:
        """Initialize output connections based on config."""
        mode = getattr(self.config.output, 'mode', 'console')

        if mode in ('udp', 'all'):
            try:
                self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                logger.info(f"UDP output ready -> {self.config.output.syslog_host}:{self.config.output.syslog_port}")
            except Exception as e:
                logger.error(f"Failed to create UDP socket: {e}")

        if mode in ('tcp', 'all'):
            try:
                self._tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._tcp_socket.settimeout(10)
                self._tcp_socket.connect((
                    self.config.output.syslog_host,
                    self.config.output.syslog_port
                ))
                logger.info(f"TCP output ready -> {self.config.output.syslog_host}:{self.config.output.syslog_port}")
            except Exception as e:
                logger.error(f"Failed to create TCP connection: {e}")
                self._tcp_socket = None

        if mode in ('file', 'all'):
            try:
                file_path = getattr(self.config.output, 'file_path', './syslog.log')
                self._file_handle = open(file_path, 'a', buffering=1)
                logger.info(f"File output ready -> {file_path}")
            except Exception as e:
                logger.error(f"Failed to open output file: {e}")

    def _weighted_choice(self, weights_dict: dict) -> str:
        """Make a weighted random choice from a dictionary."""
        items = list(weights_dict.keys())
        weights = list(weights_dict.values())
        return random.choices(items, weights=weights)[0]

    def _get_severity_for_category(self, category: str) -> str:
        """Get appropriate severity based on category context."""
        # Some categories tend to have more errors/warnings
        category_severity_bias = {
            'security': {'warning': 30, 'error': 20, 'critical': 10, 'info': 25, 'notice': 15},
            'auth': {'info': 40, 'warning': 25, 'error': 15, 'notice': 15, 'debug': 5},
            'database': {'info': 40, 'warning': 25, 'error': 20, 'notice': 10, 'debug': 5},
            'web_server': {'info': 55, 'warning': 20, 'error': 15, 'notice': 8, 'debug': 2},
            'application': {'info': 45, 'warning': 20, 'error': 15, 'notice': 10, 'debug': 10},
            'system': {'info': 50, 'notice': 20, 'warning': 15, 'error': 10, 'debug': 5},
            'network': {'info': 50, 'warning': 25, 'notice': 15, 'error': 8, 'debug': 2},
        }

        weights = category_severity_bias.get(category, self.SEVERITY_WEIGHTS)
        return self._weighted_choice(weights)

    def generate_message(self) -> dict:
        """Generate a random syslog message using templates.

        Returns:
            Dictionary containing message data
        """
        # Pick random category and hostname
        category = self._weighted_choice(self.CATEGORY_WEIGHTS)
        hostname = random.choice(self.HOSTNAMES)
        severity = self._get_severity_for_category(category)

        # Generate message based on category
        template_data = self._generate_by_category(category, hostname, severity)

        # Format RFC 3164 style raw message
        pid_str = f"[{template_data['pid']}]" if template_data.get('pid') else ""
        raw_message = f"<{template_data['priority']}>{template_data['timestamp']} {template_data['host']} {template_data['app']}{pid_str}: {template_data['message']}"

        # Build complete message data
        return {
            'message': template_data['message'],
            'raw_message': raw_message,
            'facility': FACILITIES.get(template_data['facility'], 1),
            'facility_name': template_data['facility'],
            'severity': SEVERITIES.get(template_data['severity'], 6),
            'severity_name': template_data['severity'],
            'priority': template_data['priority'],
            'hostname': template_data['host'],
            'app_name': template_data['app'],
            'pid': template_data.get('pid', 0),
            'timestamp': datetime.now(timezone.utc),
            'category': template_data.get('category', 'unknown'),
            'metadata': template_data.get('metadata', {})
        }

    def _generate_by_category(self, category: str, hostname: str, severity: str) -> dict:
        """Generate message data by category.

        Args:
            category: Message category (auth, network, etc.)
            hostname: Target hostname
            severity: Log severity level

        Returns:
            Template message dictionary
        """
        generators = {
            'auth': self._generate_auth,
            'network': self._generate_network,
            'application': self.templates.application_event,
            'system': self.templates.system_event,
            'security': self.templates.security_event,
            'database': self.templates.database_event,
            'web_server': self.templates.web_server_event,
        }

        generator = generators.get(category, self.templates.application_event)
        return generator(hostname, severity)

    def _generate_auth(self, hostname: str, severity: str) -> dict:
        """Generate auth message with appropriate type based on severity."""
        if severity in ('error', 'warning', 'critical'):
            return self.templates.auth_failure(hostname, severity)
        elif random.random() < 0.3:  # 30% chance of sudo event
            return self.templates.sudo_event(hostname, 'notice')
        else:
            return self.templates.auth_success(hostname, severity)

    def _generate_network(self, hostname: str, severity: str) -> dict:
        """Generate network message with appropriate type based on severity."""
        if severity in ('error', 'warning', 'critical'):
            return self.templates.firewall_event(hostname, severity)
        else:
            return random.choice([
                self.templates.firewall_event(hostname, severity),
                self.templates.network_connection(hostname, severity)
            ])

    def send_message(self, message_data: dict) -> None:
        """Send generated message to configured outputs.

        Args:
            message_data: Dictionary containing message data
        """
        raw_message = message_data['raw_message']
        mode = getattr(self.config.output, 'mode', 'console')

        # Console output
        if mode in ('console', 'all'):
            # Color-code by severity for better visibility
            self._print_colored(message_data)

        # UDP output
        if mode in ('udp', 'all') and self._udp_socket:
            try:
                self._udp_socket.sendto(
                    raw_message.encode('utf-8'),
                    (self.config.output.syslog_host, self.config.output.syslog_port)
                )
            except Exception as e:
                logger.error(f"UDP send error: {e}")

        # TCP output
        if mode in ('tcp', 'all') and self._tcp_socket:
            try:
                self._tcp_socket.send(f"{raw_message}\n".encode('utf-8'))
            except Exception as e:
                logger.error(f"TCP send error: {e}")
                self._reconnect_tcp()

        # File output
        if mode in ('file', 'all') and self._file_handle:
            try:
                self._file_handle.write(f"{raw_message}\n")
            except Exception as e:
                logger.error(f"File write error: {e}")

        # Elasticsearch output
        if hasattr(self.config, 'es_client') and self.config.es_client:
            try:
                self.config.es_client.index_log(
                    message=message_data.get('message', ''),
                    facility=message_data.get('facility', 1),
                    severity=message_data.get('severity', 6),
                    hostname=message_data.get('hostname', 'unknown'),
                    app_name=message_data.get('app_name', 'unknown'),
                    pid=message_data.get('pid', 0),
                    raw_message=message_data.get('raw_message', ''),
                    timestamp=message_data.get('timestamp'),
                    # Additional fields from templates
                    category=message_data.get('category'),
                    facility_name=message_data.get('facility_name'),
                    severity_name=message_data.get('severity_name'),
                    metadata=message_data.get('metadata', {})
                )
            except Exception as e:
                logger.error(f"ES indexing error: {e}")

    def _print_colored(self, message_data: dict) -> None:
        """Print message with color coding based on severity."""
        colors = {
            'emergency': '\033[91m\033[1m',  # Bold Red
            'alert': '\033[91m',              # Red
            'critical': '\033[91m',           # Red
            'error': '\033[31m',              # Dark Red
            'warning': '\033[93m',            # Yellow
            'notice': '\033[96m',             # Cyan
            'info': '\033[0m',                # Default
            'debug': '\033[90m',              # Gray
        }
        reset = '\033[0m'

        severity_name = message_data.get('severity_name', 'info')
        color = colors.get(severity_name, '')

        print(f"{color}{message_data['raw_message']}{reset}")

    def _reconnect_tcp(self) -> None:
        """Attempt to reconnect TCP socket."""
        try:
            if self._tcp_socket:
                self._tcp_socket.close()
            self._tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._tcp_socket.settimeout(10)
            self._tcp_socket.connect((
                self.config.output.syslog_host,
                self.config.output.syslog_port
            ))
            logger.info("TCP reconnected")
        except Exception as e:
            logger.error(f"TCP reconnection failed: {e}")
            self._tcp_socket = None

    def start(self) -> None:
        """Start generating messages."""
        self.running = True
        self.start_time = time.time()
        self.message_count = 0

        rate = getattr(self.config.generator, 'rate', 10)
        max_messages = getattr(self.config.generator, 'max_messages', 0)
        duration = getattr(self.config.generator, 'duration', 0)

        interval = 1.0 / rate if rate > 0 else 0

        logger.info(f"Starting generator: rate={rate}/sec, max={max_messages or 'unlimited'}, duration={duration or 'unlimited'}s")

        try:
            while self.running:
                # Check stop conditions
                if max_messages > 0 and self.message_count >= max_messages:
                    logger.info(f"Reached max messages: {max_messages}")
                    break

                if duration > 0 and (time.time() - self.start_time) >= duration:
                    logger.info(f"Reached duration: {duration}s")
                    break

                # Generate and send message
                message_data = self.generate_message()
                self.send_message(message_data)
                self.message_count += 1

                # Rate limiting
                if interval > 0:
                    time.sleep(interval)

        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        finally:
            self.stop()

    def stop(self) -> None:
        """Stop generator and cleanup."""
        self.running = False
        elapsed = time.time() - self.start_time if self.start_time else 0

        logger.info(f"Generator stopped. Sent {self.message_count} messages in {elapsed:.2f}s")

        # Flush ES buffer
        if hasattr(self.config, 'es_client') and self.config.es_client:
            try:
                self.config.es_client.flush()
                self.config.es_client.close()
            except Exception as e:
                logger.error(f"ES cleanup error: {e}")

        # Cleanup sockets/files
        if self._udp_socket:
            self._udp_socket.close()
        if self._tcp_socket:
            self._tcp_socket.close()
        if self._file_handle:
            self._file_handle.close()

    def get_stats(self) -> dict:
        """Get current generator statistics."""
        elapsed = time.time() - self.start_time if self.start_time else 0
        return {
            'messages_sent': self.message_count,
            'elapsed_seconds': elapsed,
            'rate_actual': self.message_count / elapsed if elapsed > 0 else 0,
            'running': self.running
        }


class BurstGenerator(SyslogGenerator):
    """Generator that simulates incident bursts with realistic patterns."""

    # Incident scenarios
    INCIDENT_SCENARIOS = {
        'ddos_attack': {
            'categories': ['security', 'network', 'web_server'],
            'severity_bias': {'critical': 20, 'error': 30, 'warning': 30, 'info': 20},
            'rate_multiplier': 20,
            'duration_range': (30, 120)  # 30s to 2min
        },
        'database_overload': {
            'categories': ['database', 'application'],
            'severity_bias': {'error': 40, 'warning': 35, 'critical': 15, 'info': 10},
            'rate_multiplier': 10,
            'duration_range': (60, 300)
        },
        'auth_brute_force': {
            'categories': ['auth', 'security'],
            'severity_bias': {'warning': 50, 'error': 30, 'critical': 10, 'info': 10},
            'rate_multiplier': 15,
            'duration_range': (45, 180)
        },
        'disk_failure': {
            'categories': ['system', 'database'],
            'severity_bias': {'emergency': 10, 'critical': 30, 'error': 40, 'warning': 20},
            'rate_multiplier': 5,
            'duration_range': (120, 600)
        },
        'network_outage': {
            'categories': ['network', 'application', 'web_server'],
            'severity_bias': {'error': 45, 'warning': 30, 'critical': 15, 'info': 10},
            'rate_multiplier': 8,
            'duration_range': (60, 240)
        },
        'memory_leak': {
            'categories': ['application', 'system'],
            'severity_bias': {'warning': 40, 'error': 35, 'critical': 15, 'info': 10},
            'rate_multiplier': 3,
            'duration_range': (300, 900)
        }
    }

    def __init__(self, config):
        """Initialize burst generator."""
        super().__init__(config)
        self.burst_mode = False
        self.current_incident = None
        self.burst_start_time = None
        self.burst_duration = 0
        self.affected_hosts: List[str] = []

    def start(self) -> None:
        """Start generating with burst patterns."""
        self.running = True
        self.start_time = time.time()
        self.message_count = 0

        base_rate = getattr(self.config.generator, 'rate', 10)
        max_messages = getattr(self.config.generator, 'max_messages', 0)
        duration = getattr(self.config.generator, 'duration', 0)

        logger.info(f"Starting BURST generator: base_rate={base_rate}/sec")

        try:
            while self.running:
                # Check stop conditions
                if max_messages > 0 and self.message_count >= max_messages:
                    break
                if duration > 0 and (time.time() - self.start_time) >= duration:
                    break

                # Manage burst state
                self._manage_burst_state()

                # Generate message
                message_data = self._generate_burst_message()
                self.send_message(message_data)
                self.message_count += 1

                # Adjust rate based on burst mode
                current_rate = self._get_current_rate(base_rate)
                interval = 1.0 / current_rate if current_rate > 0 else 0

                if interval > 0:
                    time.sleep(interval)

        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        finally:
            self.stop()

    def _manage_burst_state(self) -> None:
        """Manage burst mode state transitions."""
        if not self.burst_mode:
            # Random chance to start burst (0.5% per message)
            if random.random() < 0.005:
                self._start_burst()
        else:
            # Check if burst should end
            elapsed = time.time() - self.burst_start_time
            if elapsed >= self.burst_duration:
                self._end_burst()

    def _start_burst(self) -> None:
        """Start a new incident burst."""
        self.burst_mode = True
        incident_name = random.choice(list(self.INCIDENT_SCENARIOS.keys()))
        self.current_incident = self.INCIDENT_SCENARIOS[incident_name]
        self.current_incident['name'] = incident_name

        # Set burst duration
        min_dur, max_dur = self.current_incident['duration_range']
        self.burst_duration = random.randint(min_dur, max_dur)
        self.burst_start_time = time.time()

        # Select affected hosts (1-4 hosts)
        num_hosts = random.randint(1, min(4, len(self.HOSTNAMES)))
        self.affected_hosts = random.sample(self.HOSTNAMES, num_hosts)

        logger.warning(f"🔥 INCIDENT STARTED: {incident_name.upper()}")
        logger.warning(f"   Duration: ~{self.burst_duration}s | Hosts: {', '.join(self.affected_hosts)}")

    def _end_burst(self) -> None:
        """End the current burst."""
        incident_name = self.current_incident.get('name', 'unknown') if self.current_incident else 'unknown'
        logger.info(f"✓ INCIDENT RESOLVED: {incident_name.upper()}")

        self.burst_mode = False
        self.current_incident = None
        self.burst_start_time = None
        self.burst_duration = 0
        self.affected_hosts = []

    def _get_current_rate(self, base_rate: int) -> int:
        """Get current message rate based on burst state."""
        if self.burst_mode and self.current_incident:
            multiplier = self.current_incident.get('rate_multiplier', 5)
            return base_rate * multiplier
        return base_rate

    def _generate_burst_message(self) -> dict:
        """Generate message appropriate for current state."""
        if self.burst_mode and self.current_incident:
            # 85% of messages during burst are incident-related
            if random.random() < 0.85:
                return self._generate_incident_message()

        # Normal message generation
        return self.generate_message()

    def _generate_incident_message(self) -> dict:
        """Generate message specific to current incident."""
        # Pick from incident categories
        category = random.choice(self.current_incident['categories'])

        # Use incident severity bias
        severity = self._weighted_choice(self.current_incident['severity_bias'])

        # Use affected hosts
        hostname = random.choice(self.affected_hosts)

        # Generate using templates
        template_data = self._generate_by_category(category, hostname, severity)

        # Format raw message
        pid_str = f"[{template_data['pid']}]" if template_data.get('pid') else ""
        raw_message = f"<{template_data['priority']}>{template_data['timestamp']} {template_data['host']} {template_data['app']}{pid_str}: {template_data['message']}"

        return {
            'message': template_data['message'],
            'raw_message': raw_message,
            'facility': FACILITIES.get(template_data['facility'], 1),
            'facility_name': template_data['facility'],
            'severity': SEVERITIES.get(template_data['severity'], 6),
            'severity_name': template_data['severity'],
            'priority': template_data['priority'],
            'hostname': template_data['host'],
            'app_name': template_data['app'],
            'pid': template_data.get('pid', 0),
            'timestamp': datetime.now(timezone.utc),
            'category': template_data.get('category', 'unknown'),
            'metadata': {
                **template_data.get('metadata', {}),
                'incident': self.current_incident.get('name'),
                'incident_active': True
            }
        }


class ScenarioGenerator(SyslogGenerator):
    """Generator that runs specific predefined scenarios."""

    def __init__(self, config, scenario: str = 'normal'):
        """Initialize scenario generator.

        Args:
            config: Configuration object
            scenario: Scenario name to run
        """
        super().__init__(config)
        self.scenario = scenario

    def start(self) -> None:
        """Start scenario-based generation."""
        scenarios = {
            'normal': self._run_normal,
            'high_error': self._run_high_error,
            'auth_attack': self._run_auth_attack,
            'db_issues': self._run_db_issues,
            'web_traffic': self._run_web_traffic,
        }

        runner = scenarios.get(self.scenario, self._run_normal)

        logger.info(f"Starting SCENARIO generator: {self.scenario}")

        try:
            runner()
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        finally:
            self.stop()

    def _run_normal(self) -> None:
        """Run normal balanced scenario."""
        # Just use default behavior
        super().start()

    def _run_high_error(self) -> None:
        """Run high error rate scenario."""
        self.SEVERITY_WEIGHTS = {
            'debug': 2, 'info': 20, 'notice': 10,
            'warning': 25, 'error': 30, 'critical': 10, 'alert': 2, 'emergency': 1
        }
        super().start()

    def _run_auth_attack(self) -> None:
        """Run authentication attack scenario."""
        self.CATEGORY_WEIGHTS = {
            'auth': 60, 'security': 25, 'network': 10,
            'application': 2, 'system': 2, 'database': 1, 'web_server': 0
        }
        self.SEVERITY_WEIGHTS = {
            'debug': 0, 'info': 10, 'notice': 10,
            'warning': 40, 'error': 30, 'critical': 8, 'alert': 2, 'emergency': 0
        }
        super().start()

    def _run_db_issues(self) -> None:
        """Run database issues scenario."""
        self.CATEGORY_WEIGHTS = {
            'database': 50, 'application': 30, 'system': 10,
            'auth': 5, 'network': 3, 'security': 1, 'web_server': 1
        }
        super().start()

    def _run_web_traffic(self) -> None:
        """Run high web traffic scenario."""
        self.CATEGORY_WEIGHTS = {
            'web_server': 60, 'application': 25, 'network': 10,
            'auth': 2, 'system': 2, 'database': 1, 'security': 0
        }
        super().start()
