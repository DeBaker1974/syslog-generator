# syslog_generator/generator.py
"""Core syslog message generator engine."""

import random
import time
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Callable, Optional
from dataclasses import dataclass, field
from collections import deque

from .templates import MessageTemplates, SEVERITIES
from .senders import MessageSender, create_sender
from .config import AppConfig


@dataclass
class GeneratorStats:
    """Statistics tracking for the generator."""
    messages_sent: int = 0
    messages_failed: int = 0
    start_time: datetime = field(default_factory=datetime.now)
    messages_by_category: Dict[str, int] = field(default_factory=dict)
    messages_by_severity: Dict[str, int] = field(default_factory=dict)
    recent_rates: deque = field(default_factory=lambda: deque(maxlen=60))
    
    def record_message(self, category: str, severity: str, success: bool):
        """Record a sent message in stats."""
        if success:
            self.messages_sent += 1
            self.messages_by_category[category] = self.messages_by_category.get(category, 0) + 1
            self.messages_by_severity[severity] = self.messages_by_severity.get(severity, 0) + 1
        else:
            self.messages_failed += 1
    
    def get_runtime(self) -> timedelta:
        """Get total runtime."""
        return datetime.now() - self.start_time
    
    def get_rate(self) -> float:
        """Get current messages per second rate."""
        runtime = self.get_runtime().total_seconds()
        if runtime > 0:
            return self.messages_sent / runtime
        return 0.0
    
    def get_summary(self) -> str:
        """Get a formatted summary of statistics."""
        runtime = self.get_runtime()
        rate = self.get_rate()
        
        lines = [
            "\n" + "=" * 60,
            "GENERATOR STATISTICS",
            "=" * 60,
            f"Runtime:          {runtime}",
            f"Messages Sent:    {self.messages_sent:,}",
            f"Messages Failed:  {self.messages_failed:,}",
            f"Average Rate:     {rate:.2f} msg/sec",
            "",
            "Messages by Category:",
        ]
        
        for cat, count in sorted(self.messages_by_category.items(), key=lambda x: -x[1]):
            pct = (count / self.messages_sent * 100) if self.messages_sent > 0 else 0
            lines.append(f"  {cat:20} {count:8,} ({pct:5.1f}%)")
        
        lines.append("")
        lines.append("Messages by Severity:")
        
        for sev, count in sorted(self.messages_by_severity.items(), 
                                  key=lambda x: SEVERITIES.get(x[0], 99)):
            pct = (count / self.messages_sent * 100) if self.messages_sent > 0 else 0
            lines.append(f"  {sev:20} {count:8,} ({pct:5.1f}%)")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)


class SyslogGenerator:
    """Main syslog message generator."""
    
    def __init__(self, config: AppConfig):
        self.config = config
        self.templates = MessageTemplates()
        self.sender: Optional[MessageSender] = None
        self.stats = GeneratorStats()
        self._running = False
        self._paused = False
        self._lock = threading.Lock()
        
        # Build severity weights from config
        self.severity_weights = self._build_severity_weights()
        
        # Build message generators based on enabled profiles
        self.message_generators = self._build_message_generators()
        
        logging.info(f"Generator initialized with {len(self.message_generators)} message types")
    
    def _build_severity_weights(self) -> List[tuple]:
        """Build weighted list of severities."""
        weights = []
        for severity, weight in self.config.severity_distribution.items():
            if weight > 0:
                weights.append((severity, weight))
        return weights
    
    def _weighted_severity(self) -> str:
        """Select a severity level based on weights."""
        severities, weights = zip(*self.severity_weights)
        return random.choices(severities, weights=weights)[0]
    
    def _build_message_generators(self) -> List[Callable]:
        """Build list of message generator functions based on config."""
        generators = []
        profiles = self.config.message_profiles
        
        if profiles.get('auth_logs', True):
            generators.extend([
                ('auth', self.templates.auth_success),
                ('auth', self.templates.auth_failure),
                ('auth', self.templates.sudo_event),
            ])
        
        if profiles.get('network_logs', True):
            generators.extend([
                ('network', self.templates.firewall_event),
                ('network', self.templates.network_connection),
            ])
        
        if profiles.get('application_logs', True):
            generators.extend([
                ('application', self.templates.application_event),
            ])
        
        if profiles.get('system_logs', True):
            generators.extend([
                ('system', self.templates.system_event),
            ])
        
        if profiles.get('security_logs', True):
            generators.extend([
                ('security', self.templates.security_event),
            ])
        
        if profiles.get('database_logs', True):
            generators.extend([
                ('database', self.templates.database_event),
            ])
        
        if profiles.get('web_server_logs', True):
            generators.extend([
                ('web_server', self.templates.web_server_event),
            ])
        
        return generators
    
    def _select_host(self) -> str:
        """Select a random host from configuration."""
        return random.choice(self.config.hosts) if self.config.hosts else "localhost"
    
    def _generate_message(self) -> Dict:
        """Generate a single syslog message."""
        # Select random generator and severity
        category, generator_func = random.choice(self.message_generators)
        severity = self._weighted_severity()
        host = self._select_host()
        
        # Some generators work better with specific severities
        if category in ['auth'] and generator_func == self.templates.auth_failure:
            severity = random.choice(['warning', 'error', 'notice'])
        elif category in ['security']:
            severity = random.choice(['warning', 'error', 'critical', 'alert'])
        
        # Generate the message
        message_data = generator_func(host, severity)
        return message_data
    
    def generate_batch(self, count: int) -> List[Dict]:
        """Generate a batch of messages."""
        return [self._generate_message() for _ in range(count)]
    
    def start(self) -> None:
        """Start the generator."""
        self.sender = create_sender(self.config)
        self._running = True
        self._paused = False
        self.stats = GeneratorStats()
        
        rate = self.config.generator.rate
        max_messages = self.config.generator.max_messages
        duration = self.config.generator.duration
        
        logging.info(f"Starting generator: rate={rate}/s, max={max_messages}, duration={duration}s")
        print(f"\n{'='*60}")
        print("SYSLOG GENERATOR STARTED")
        print(f"{'='*60}")
        print(f"Output Mode:     {self.config.output.mode}")
        print(f"Target Rate:     {rate} messages/second")
        print(f"Max Messages:    {'Unlimited' if max_messages == 0 else max_messages}")
        print(f"Duration:        {'Unlimited' if duration == 0 else f'{duration} seconds'}")
        print(f"Hosts:           {len(self.config.hosts)} configured")
        print(f"Message Types:   {len(self.message_generators)} enabled")
        print(f"{'='*60}")
        print("Press Ctrl+C to stop...\n")
        
        # Calculate sleep interval
        if rate > 0:
            interval = 1.0 / rate
        else:
            interval = 1.0
        
        message_count = 0
        start_time = time.time()
        last_status_time = start_time
        
        try:
            while self._running:
                # Check if paused
                if self._paused:
                    time.sleep(0.1)
                    continue
                
                # Check max messages limit
                if max_messages > 0 and message_count >= max_messages:
                    logging.info(f"Reached max messages limit: {max_messages}")
                    break
                
                # Check duration limit
                if duration > 0 and (time.time() - start_time) >= duration:
                    logging.info(f"Reached duration limit: {duration}s")
                    break
                
                # Generate and send message
                message_data = self._generate_message()
                success = self.sender.send(message_data)
                
                with self._lock:
                    self.stats.record_message(
                        message_data.get('category', 'unknown'),
                        message_data.get('severity', 'info'),
                        success
                    )
                
                message_count += 1
                
                # Print periodic status update (every 10 seconds)
                current_time = time.time()
                if current_time - last_status_time >= 10:
                    elapsed = current_time - start_time
                    current_rate = message_count / elapsed if elapsed > 0 else 0
                    print(f"[STATUS] Messages: {message_count:,} | "
                          f"Rate: {current_rate:.1f}/s | "
                          f"Elapsed: {elapsed:.0f}s")
                    last_status_time = current_time
                
                # Rate limiting
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\nReceived interrupt signal...")
        finally:
            self.stop()
    
    def stop(self) -> None:
        """Stop the generator and cleanup."""
        self._running = False
        
        if self.sender:
            self.sender.close()
        
        # Print final statistics
        print(self.stats.get_summary())
    
    def pause(self) -> None:
        """Pause message generation."""
        self._paused = True
        logging.info("Generator paused")
    
    def resume(self) -> None:
        """Resume message generation."""
        self._paused = False
        logging.info("Generator resumed")
    
    def get_stats(self) -> GeneratorStats:
        """Get current statistics."""
        return self.stats


class BurstGenerator(SyslogGenerator):
    """Generator that creates bursts of related messages (simulating incidents)."""
    
    def __init__(self, config: AppConfig):
        super().__init__(config)
        self.incident_probability = 0.05  # 5% chance of incident burst
    
    def _generate_incident_burst(self) -> List[Dict]:
        """Generate a burst of related incident messages."""
        incident_types = [
            self._brute_force_incident,
            self._service_outage_incident,
            self._disk_space_incident,
            self._ddos_incident,
        ]
        
        incident_func = random.choice(incident_types)
        return incident_func()
    
    def _brute_force_incident(self) -> List[Dict]:
        """Simulate a brute force attack incident."""
        messages = []
        attacker_ip = self.templates.fake.ipv4()
        host = self._select_host()
        
        # Multiple failed login attempts
        for i in range(random.randint(5, 20)):
            msg = self.templates.auth_failure(host, 'warning')
            # Override with consistent attacker IP
            msg['message'] = msg['message'].replace(
                msg['message'].split('from ')[1].split(' ')[0] if 'from ' in msg['message'] else '',
                attacker_ip
            )
            messages.append(msg)
        
        # Security alert
        messages.append(self.templates.security_event(host, 'alert'))
        
        # Potential ban
        if random.random() > 0.3:
            ban_msg = {
                'priority': 37,
                'timestamp': self.templates._get_timestamp(),
                'host': host,
                'app': 'fail2ban',
                'pid': random.randint(1000, 65535),
                'message': f"NOTICE [sshd] Ban {attacker_ip}",
                'facility': 'authpriv',
                'severity': 'notice',
                'category': 'security'
            }
            messages.append(ban_msg)
        
        return messages
    
    def _service_outage_incident(self) -> List[Dict]:
        """Simulate a service outage incident."""
        messages = []
        host = self._select_host()
        service = random.choice(['nginx', 'postgresql', 'redis', 'api-gateway'])
        
        # Warning signs
        for _ in range(random.randint(2, 5)):
            messages.append(self.templates.application_event(host, 'warning'))
        
        # Service failure
        messages.append({
            'priority': self.templates._calculate_priority('daemon', 'error'),
            'timestamp': self.templates._get_timestamp(),
            'host': host,
            'app': 'systemd',
            'pid': 1,
            'message': f"{service}.service: Main process exited, code=exited, status=1/FAILURE",
            'facility': 'daemon',
            'severity': 'error',
            'category': 'system'
        })
        
        # Downstream effects
        for _ in range(random.randint(3, 8)):
            messages.append(self.templates.web_server_event(host, 'error'))
        
        # Recovery attempt
        messages.append({
            'priority': self.templates._calculate_priority('daemon', 'notice'),
            'timestamp': self.templates._get_timestamp(),
            'host': host,
            'app': 'systemd',
            'pid': 1,
            'message': f"{service}.service: Scheduled restart job, restart counter is at {random.randint(1, 5)}.",
            'facility': 'daemon',
            'severity': 'notice',
            'category': 'system'
        })
        
        return messages
    
    def _disk_space_incident(self) -> List[Dict]:
        """Simulate a disk space critical incident."""
        messages = []
        host = self._select_host()
        
        # Warnings leading up
        for pct in [85, 90, 95, 98]:
            messages.append({
                'priority': self.templates._calculate_priority('kern', 'warning' if pct < 95 else 'critical'),
                'timestamp': self.templates._get_timestamp(),
                'host': host,
                'app': 'monitoring',
                'pid': random.randint(1000, 65535),
                'message': f"Disk usage on /var/log reached {pct}%",
                'facility': 'kern',
                'severity': 'warning' if pct < 95 else 'critical',
                'category': 'system'
            })
        
        # Application errors due to disk space
        for _ in range(random.randint(2, 5)):
            messages.append(self.templates.database_event(host, 'error'))
        
        return messages
    
    def _ddos_incident(self) -> List[Dict]:
        """Simulate a DDoS attack incident."""
        messages = []
        host = self._select_host()
        
        # High volume of connections
        for _ in range(random.randint(10, 30)):
            messages.append(self.templates.firewall_event(host, 'warning'))
        
        # Load balancer warnings
        messages.append({
            'priority': self.templates._calculate_priority('local7', 'warning'),
            'timestamp': self.templates._get_timestamp(),
            'host': host,
            'app': 'haproxy',
            'pid': random.randint(1000, 65535),
            'message': f"backend app_servers has no server available!",
            'facility': 'local7',
            'severity': 'warning',
            'category': 'web_server'
        })
        
        # Security alerts
        for _ in range(random.randint(2, 5)):
            messages.append(self.templates.security_event(host, 'alert'))
        
        return messages
    
    def start(self) -> None:
        """Start the burst generator."""
        self.sender = create_sender(self.config)
        self._running = True
        self._paused = False
        self.stats = GeneratorStats()
        
        rate = self.config.generator.rate
        max_messages = self.config.generator.max_messages
        duration = self.config.generator.duration
        
        logging.info(f"Starting BURST generator: rate={rate}/s")
        print(f"\n{'='*60}")
        print("SYSLOG BURST GENERATOR STARTED")
        print(f"{'='*60}")
        print(f"Mode: Burst (simulates incidents)")
        print(f"Incident Probability: {self.incident_probability * 100}%")
        print(f"{'='*60}\n")
        
        interval = 1.0 / rate if rate > 0 else 1.0
        message_count = 0
        start_time = time.time()
        
        try:
            while self._running:
                if self._paused:
                    time.sleep(0.1)
                    continue
                
                if max_messages > 0 and message_count >= max_messages:
                    break
                
                if duration > 0 and (time.time() - start_time) >= duration:
                    break
                
                # Decide if we should generate an incident burst
                if random.random() < self.incident_probability:
                    print("\n[INCIDENT] Generating incident burst...")
                    burst_messages = self._generate_incident_burst()
                    for msg in burst_messages:
                        success = self.sender.send(msg)
                        self.stats.record_message(
                            msg.get('category', 'unknown'),
                            msg.get('severity', 'info'),
                            success
                        )
                        message_count += 1
                        time.sleep(interval / 2)  # Faster during bursts
                else:
                    # Normal message
                    message_data = self._generate_message()
                    success = self.sender.send(message_data)
                    self.stats.record_message(
                        message_data.get('category', 'unknown'),
                        message_data.get('severity', 'info'),
                        success
                    )
                    message_count += 1
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\nReceived interrupt signal...")
        finally:
            self.stop()
