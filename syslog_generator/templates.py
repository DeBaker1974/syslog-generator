# syslog_generator/templates.py
"""Syslog message templates for various log types."""

import random
from datetime import datetime
from faker import Faker
from typing import Dict, List, Tuple

fake = Faker()

# Syslog Facility Codes
FACILITIES = {
    'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
    'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
    'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
    'ntp': 12, 'security': 13, 'console': 14, 'solaris-cron': 15,
    'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
    'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23
}

# Syslog Severity Codes
SEVERITIES = {
    'emergency': 0, 'alert': 1, 'critical': 2, 'error': 3,
    'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
}

# HTTP Status Codes with weights
HTTP_STATUS_CODES = [
    (200, 60), (201, 10), (204, 5), (301, 3), (302, 5),
    (304, 8), (400, 3), (401, 2), (403, 2), (404, 5),
    (500, 2), (502, 1), (503, 1), (504, 1)
]

# Common application names
APPS = {
    'auth': ['sshd', 'sudo', 'login', 'su', 'pam', 'systemd-logind'],
    'network': ['NetworkManager', 'dhclient', 'firewalld', 'iptables', 'named', 'dnsmasq'],
    'application': ['myapp', 'api-gateway', 'user-service', 'payment-service', 'notification-service'],
    'system': ['kernel', 'systemd', 'cron', 'rsyslogd', 'auditd'],
    'security': ['fail2ban', 'snort', 'ossec', 'clamd', 'aide'],
    'database': ['mysqld', 'postgresql', 'mongodb', 'redis-server', 'elasticsearch'],
    'web_server': ['nginx', 'apache2', 'httpd', 'haproxy', 'varnish']
}

class MessageTemplates:
    """Generate realistic syslog messages for various categories."""
    
    def __init__(self):
        self.fake = Faker()
        
    def _calculate_priority(self, facility: str, severity: str) -> int:
        """Calculate syslog priority value."""
        return (FACILITIES.get(facility, 1) * 8) + SEVERITIES.get(severity, 6)
    
    def _get_timestamp(self) -> str:
        """Generate RFC 3164 timestamp."""
        return datetime.now().strftime("%b %d %H:%M:%S")
    
    def _get_iso_timestamp(self) -> str:
        """Generate RFC 5424 timestamp."""
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    
    def _weighted_choice(self, choices: List[Tuple]) -> any:
        """Make a weighted random choice."""
        items, weights = zip(*choices)
        return random.choices(items, weights=weights)[0]
    
    # ==================== AUTH LOGS ====================
    
    def auth_success(self, host: str, severity: str = 'info') -> Dict:
        """Successful authentication message."""
        app = random.choice(APPS['auth'])
        user = self.fake.user_name()
        ip = self.fake.ipv4()
        port = random.randint(1024, 65535)
        
        templates = [
            f"Accepted publickey for {user} from {ip} port {port} ssh2: RSA SHA256:{self.fake.sha256()[:43]}",
            f"Accepted password for {user} from {ip} port {port} ssh2",
            f"pam_unix({app}:session): session opened for user {user} by (uid=0)",
            f"New session 1 of user {user}.",
            f"User {user} logged in successfully from {ip}",
        ]
        
        return {
            'priority': self._calculate_priority('authpriv', severity),
            'timestamp': self._get_timestamp(),
            'host': host,
            'app': app,
            'pid': random.randint(1000, 65535),
            'message': random.choice(templates),
            'facility': 'authpriv',
            'severity': severity,
            'category': 'auth'
        }
    
    def auth_failure(self, host: str, severity: str = 'warning') -> Dict:
        """Failed authentication message."""
        app = random.choice(APPS['auth'])
        user = self.fake.user_name()
        ip = self.fake.ipv4()
        port = random.randint(1024, 65535)
        
        templates = [
            f"Failed password for {user} from {ip} port {port} ssh2",
            f"Failed password for invalid user {user} from {ip} port {port} ssh2",
            f"pam_unix({app}:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip} user={user}",
            f"Invalid user {user} from {ip} port {port}",
            f"Connection closed by authenticating user {user} {ip} port {port} [preauth]",
            f"error: maximum authentication attempts exceeded for {user} from {ip} port {port} ssh2 [preauth]",
            f"Disconnecting invalid user {user} {ip} port {port}: Too many authentication failures",
        ]
        
        return {
            'priority': self._calculate_priority('authpriv', severity),
            'timestamp': self._get_timestamp(),
            'host': host,
            'app': app,
            'pid': random.randint(1000, 65535),
            'message': random.choice(templates),
            'facility': 'authpriv',
            'severity': severity,
            'category': 'auth'
        }
    
    def sudo_event(self, host: str, severity: str = 'notice') -> Dict:
        """Sudo command execution."""
        user = self.fake.user_name()
        target_user = random.choice(['root', 'www-data', 'postgres', user])
        commands = [
            '/bin/systemctl restart nginx',
            '/usr/bin/apt update',
            '/bin/cat /etc/shadow',
            '/usr/bin/vim /etc/hosts',
            '/bin/chmod 755 /var/www',
            '/usr/bin/docker ps',
            '/bin/journalctl -xe',
            f'/usr/bin/kill -9 {random.randint(1000, 65535)}'
        ]
        
        return {
            'priority': self._calculate_priority('authpriv', severity),
            'timestamp': self._get_timestamp(),
            'host': host,
            'app': 'sudo',
            'pid': random.randint(1000, 65535),
            'message': f"{user} : TTY=pts/{random.randint(0, 10)} ; PWD=/home/{user} ; USER={target_user} ; COMMAND={random.choice(commands)}",
            'facility': 'authpriv',
            'severity': severity,
            'category': 'auth'
        }
    
    # ==================== NETWORK LOGS ====================
    
    def firewall_event(self, host: str, severity: str = 'warning') -> Dict:
        """Firewall block/allow events."""
        src_ip = self.fake.ipv4()
        dst_ip = self.fake.ipv4_private()
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([22, 80, 443, 3306, 5432, 6379, 8080, 9200])
        protocol = random.choice(['TCP', 'UDP', 'ICMP'])
        action = random.choices(['BLOCK', 'DROP', 'REJECT', 'ACCEPT'], weights=[40, 30, 10, 20])[0]
        interface = random.choice(['eth0', 'eth1', 'ens192', 'ens160'])
        
        templates = [
            f"[UFW {action}] IN={interface} OUT= MAC={self.fake.mac_address()} SRC={src_ip} DST={dst_ip} LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID={random.randint(1, 65535)} DF PROTO={protocol} SPT={src_port} DPT={dst_port}",
            f"iptables: {action} IN={interface} SRC={src_ip} DST={dst_ip} PROTO={protocol} DPT={dst_port}",
            f"firewalld: {action.lower()} {protocol.lower()} -- {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
        ]
        
        return {
            'priority': self._calculate_priority('kern', severity),
            'timestamp': self._get_timestamp(),
            'host': host,
            'app': random.choice(['kernel', 'firewalld', 'ufw']),
            'pid': None,
            'message': random.choice(templates),
            'facility': 'kern',
            'severity': severity,
            'category': 'network',
            'metadata': {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'action': action
            }
        }
    
    def network_connection(self, host: str, severity: str = 'info') -> Dict:
        """Network connection events."""
        interface = random.choice(['eth0', 'eth1', 'ens192', 'wlan0'])
        ip = self.fake.ipv4_private()
        gateway = '.'.join(ip.split('.')[:3]) + '.1'
        dns = random.choice(['8.8.8.8', '8.8.4.4', '1.1.1.1', gateway])
        
        templates = [
            f"NetworkManager: <info> ({interface}): Activation: successful, device activated.",
            f"dhclient: DHCPACK from {gateway} (xid=0x{self.fake.hexify(text='^^^^^^^^')})",
            f"dhclient: bound to {ip} -- renewal in {random.randint(1800, 43200)} seconds.",
            f"NetworkManager: <info> ({interface}): device state change: ip-config -> activated",
            f"systemd-networkd: {interface}: Gained IPv4LL address {ip}",
            f"dnsmasq: using nameserver {dns}#53 for domain .",
        ]
        
        return {
            'priority': self._calculate_priority('daemon', severity),
            'timestamp': self._get_timestamp(),
            'host': host,
            'app': random.choice(APPS['network']),
            'pid': random.randint(1000, 65535),
            'message': random.choice(templates),
            'facility': 'daemon',
            'severity': severity,
            'category': 'network'
        }
    
    # ==================== APPLICATION LOGS ====================
    
    def application_event(self, host: str, severity: str = 'info') -> Dict:
        """Generic application events."""
        app = random.choice(APPS['application'])
        request_id = self.fake.uuid4()[:8]
        user_id = random.randint(1000, 999999)
        latency = round(random.uniform(0.1, 500), 2)
        
        info_templates = [
            f"[{request_id}] Request processed successfully in {latency}ms",
            f"[{request_id}] User {user_id} session started",
            f"[{request_id}] Cache hit for key user:{user_id}:profile",
            f"[{request_id}] Background job completed: send_notification",
            f"[{request_id}] Health check passed - all dependencies healthy",
            f"[{request_id}] Configuration reloaded successfully",
        ]
        
        warning_templates = [
            f"[{request_id}] Slow query detected: {latency}ms exceeded threshold",
            f"[{request_id}] Rate limit approaching for user {user_id}",
            f"[{request_id}] Retry attempt 2/3 for external API call",
            f"[{request_id}] Memory usage at 85% - consider scaling",
            f"[{request_id}] Deprecated API endpoint accessed: /api/v1/legacy",
        ]
        
        error_templates = [
            f"[{request_id}] NullPointerException in UserService.getProfile()",
            f"[{request_id}] Database connection pool exhausted",
            f"[{request_id}] Failed to process payment for order {random.randint(10000, 99999)}",
            f"[{request_id}] Timeout waiting for response from auth-service",
            f"[{request_id}] Invalid JSON payload received",
            f"[{request_id}] Circuit breaker OPEN for payment-gateway",
        ]
        
        templates = {
            'info': info_templates,
            'notice': info_templates,
            'debug': info_templates,
            'warning': warning_templates,
            'error': error_templates,
            'critical': error_templates,
            'alert': error_templates,
            'emergency': error_templates,
        }
        
        return {
            'priority': self._calculate_priority('local0', severity),
            'timestamp': self._get_timestamp(),
            'host': host,
            'app': app,
            'pid': random.randint(1000, 65535),
            'message': random.choice(templates.get(severity, info_templates)),
            'facility': 'local0',
            'severity': severity,
            'category': 'application',
            'metadata': {
                'request_id': request_id,
                'latency_ms': latency
            }
        }
    
    # ==================== SYSTEM LOGS ====================
    
    def system_event(self, host: str, severity: str = 'info') -> Dict:
        """System-level events."""
        cpu = random.randint(0, 100)
        memory = random.randint(0, 100)
        disk = random.randint(0, 100)
        load = round(random.uniform(0, 16), 2)
        
        templates = [
            f"systemd: Started Session {random.randint(1, 1000)} of user {self.fake.user_name()}.",
            f"systemd: Starting Daily apt download activities...",
            f"kernel: [  {random.uniform(0, 99999):.6f}] CPU{random.randint(0, 7)}: Core temperature above threshold, cpu clock throttled",
            f"CRON[{random.randint(1000, 65535)}]: (root) CMD (/usr/local/bin/backup.sh)",
            f"rsyslogd: [origin software=\"rsyslogd\"] rsyslogd was HUPed",
            f"systemd: Stopped target Graphical Interface.",
            f"kernel: Out of memory: Killed process {random.randint(1000, 65535)} ({random.choice(APPS['application'])})",
            f"systemd-journald: Runtime journal is using {random.uniform(1, 8):.1f}M",
        ]
        
        if severity in ['warning', 'error', 'critical']:
            templates = [
                f"kernel: [  {random.uniform(0, 99999):.6f}] EXT4-fs error (device sda1): ext4_lookup:1590: inode #{random.randint(1000, 999999)}",
                f"systemd: nginx.service: Failed with result 'exit-code'.",
                f"kernel: [  {random.uniform(0, 99999):.6f}] CPU{random.randint(0, 7)}: Package temperature above threshold",
                f"systemd: Failed to start The Apache HTTP Server.",
                f"kernel: NMI: PCI system error (SERR) on bus 00, device 00, function 00",
                f"kernel: ata1.00: exception Emask 0x0 SAct 0x1 SErr 0x0 action 0x0",
            ]
        
        return {
            'priority': self._calculate_priority('kern', severity),
            'timestamp': self._get_timestamp(),
            'host': host,
            'app': random.choice(APPS['system']),
            'pid': random.randint(1, 65535) if random.random() > 0.3 else None,
            'message': random.choice(templates),
            'facility': 'kern',
            'severity': severity,
            'category': 'system',
            'metadata': {
                'cpu_percent': cpu,
                'memory_percent': memory,
                'load_average': load
            }
        }
    
    # ==================== SECURITY LOGS ====================
    
# syslog_generator/templates.py (continued)

    def security_event(self, host: str, severity: str = 'warning') -> Dict:
        """Security-related events (IDS/IPS, antivirus, etc.)."""
        src_ip = self.fake.ipv4()
        attack_types = [
            'SQL Injection', 'XSS Attack', 'Directory Traversal',
            'Brute Force', 'Port Scan', 'DDoS', 'Buffer Overflow',
            'Command Injection', 'CSRF', 'LFI/RFI'
        ]
        
        malware_names = [
            'Trojan.Generic', 'Worm.Conficker', 'Ransomware.WannaCry',
            'Backdoor.Agent', 'Rootkit.Hidden', 'Spyware.Keylogger',
            'Adware.BrowserHelper', 'Cryptominer.CoinHive'
        ]
        
        templates = [
            f"fail2ban.actions: NOTICE [sshd] Ban {src_ip}",
            f"fail2ban.filter: INFO [sshd] Found {src_ip} - {datetime.now().isoformat()}",
            f"snort: [**] [1:{random.randint(1000, 9999)}:{random.randint(1, 10)}] {random.choice(attack_types)} attempt detected [**] {{TCP}} {src_ip}:{random.randint(1024, 65535)} -> {self.fake.ipv4_private()}:{random.choice([80, 443, 8080])}",
            f"ossec: Alert Level: {random.randint(5, 15)}; Rule: {random.randint(1000, 9999)} - {random.choice(attack_types)} detected; Src IP: {src_ip}",
            f"clamd: {self.fake.file_path()} FOUND {random.choice(malware_names)}",
            f"aide: Entry {self.fake.file_path()}: permissions changed from 0644 to 0777",
            f"audit: USER_AUTH pid={random.randint(1000, 65535)} uid=0 auid={random.randint(1000, 9999)} msg='op=PAM:authentication acct=\"{self.fake.user_name()}\" exe=\"/usr/sbin/sshd\" hostname={src_ip} addr={src_ip} res=failed'",
            f"suricata: [Drop] [{random.randint(1, 100)}:{random.randint(1000, 9999)}:{random.randint(1, 5)}] ET SCAN Potential SSH Scan {src_ip} -> {self.fake.ipv4_private()}",
        ]
        
        return {
            'priority': self._calculate_priority('security', severity),
            'timestamp': self._get_timestamp(),
            'host': host,
            'app': random.choice(APPS['security']),
            'pid': random.randint(1000, 65535),
            'message': random.choice(templates),
            'facility': 'security',
            'severity': severity,
            'category': 'security',
            'metadata': {
                'src_ip': src_ip,
                'attack_type': random.choice(attack_types)
            }
        }
    
    # ==================== DATABASE LOGS ====================
    
    def database_event(self, host: str, severity: str = 'info') -> Dict:
        """Database server events."""
        db_app = random.choice(APPS['database'])
        db_name = random.choice(['users_db', 'orders_db', 'inventory_db', 'analytics_db', 'sessions_db'])
        table = random.choice(['users', 'orders', 'products', 'sessions', 'logs', 'transactions'])
        query_time = round(random.uniform(0.001, 30.0), 3)
        rows = random.randint(1, 100000)
        connections = random.randint(1, 500)
        
        info_templates = [
            f"[Note] {db_app}: ready for connections. Version: '8.0.{random.randint(20, 35)}' socket: '/var/run/mysqld/mysqld.sock' port: 3306",
            f"LOG: connection received: host={self.fake.ipv4_private()} port={random.randint(1024, 65535)}",
            f"LOG: statement: SELECT * FROM {table} WHERE id = {random.randint(1, 99999)}",
            f"LOG: duration: {query_time} ms",
            f"[Note] InnoDB: Buffer pool(s) load completed at {datetime.now().strftime('%y%m%d %H:%M:%S')}",
            f"LOG: checkpoint complete: wrote {random.randint(100, 10000)} buffers",
            f"Slow query: {query_time}s - SELECT * FROM {table} WHERE created_at > '2024-01-01'",
        ]
        
        warning_templates = [
            f"[Warning] Aborted connection {random.randint(1000, 99999)} to db: '{db_name}' user: '{self.fake.user_name()}' host: '{self.fake.ipv4()}' (Got timeout reading communication packets)",
            f"LOG: could not receive data from client: Connection reset by peer",
            f"[Warning] IP address '{self.fake.ipv4()}' could not be resolved: Name or service not known",
            f"LOG: process {random.randint(1000, 65535)} still waiting for ShareLock on transaction {random.randint(100000, 999999)} after {random.randint(1000, 30000)} ms",
            f"WARNING: connection pool exhausted, {connections} active connections",
            f"[Warning] Changed limits: max_connections: {connections} (was {connections - 50})",
        ]
        
        error_templates = [
            f"[ERROR] InnoDB: Unable to lock ./ibdata1 error: {random.randint(1, 100)}",
            f"ERROR: relation \"{table}\" does not exist at character {random.randint(1, 100)}",
            f"[ERROR] {db_app}: Table '{db_name}.{table}' doesn't exist",
            f"FATAL: password authentication failed for user \"{self.fake.user_name()}\"",
            f"[ERROR] Disk full (/var/lib/mysql/#sql_{random.randint(1000, 9999)}_{random.randint(0, 100)}.MAI)",
            f"ERROR: deadlock detected; Details: Process {random.randint(1000, 65535)} waits for ShareLock on relation {table}",
            f"[ERROR] InnoDB: Corruption in table {db_name}.{table}",
        ]
        
        templates = {
            'info': info_templates,
            'notice': info_templates,
            'debug': info_templates,
            'warning': warning_templates,
            'error': error_templates,
            'critical': error_templates,
            'alert': error_templates,
            'emergency': error_templates,
        }
        
        return {
            'priority': self._calculate_priority('daemon', severity),
            'timestamp': self._get_timestamp(),
            'host': host,
            'app': db_app,
            'pid': random.randint(1000, 65535),
            'message': random.choice(templates.get(severity, info_templates)),
            'facility': 'daemon',
            'severity': severity,
            'category': 'database',
            'metadata': {
                'database': db_name,
                'query_time_ms': query_time * 1000,
                'connections': connections
            }
        }
    
    # ==================== WEB SERVER LOGS ====================
    
    def web_server_event(self, host: str, severity: str = 'info') -> Dict:
        """Web server access and error logs."""
        client_ip = self.fake.ipv4()
        method = random.choices(
            ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'],
            weights=[60, 20, 8, 5, 3, 2, 2]
        )[0]
        
        paths = [
            '/', '/index.html', '/api/v1/users', '/api/v1/orders',
            '/api/v1/products', '/api/v2/health', '/static/js/app.js',
            '/static/css/style.css', '/images/logo.png', '/favicon.ico',
            '/api/v1/auth/login', '/api/v1/auth/logout', '/admin/dashboard',
            '/graphql', '/metrics', '/api/v1/search?q=test'
        ]
        
        status = self._weighted_choice(HTTP_STATUS_CODES)
        response_time = round(random.uniform(0.001, 5.0), 3)
        bytes_sent = random.randint(100, 500000)
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'curl/7.68.0',
            'python-requests/2.28.0',
            'PostmanRuntime/7.29.0',
            'Apache-HttpClient/4.5.13',
        ]
        
        # Combined Log Format (CLF)
        access_log = f'{client_ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S %z")}] "{method} {random.choice(paths)} HTTP/1.1" {status} {bytes_sent} "-" "{random.choice(user_agents)}" {response_time}'
        
        info_templates = [
            access_log,
            f"[notice] {random.randint(1000, 65535)}#{random.randint(0, 100)}: signal process started",
            f"[notice] nginx/{random.randint(1, 2)}.{random.randint(14, 25)}.{random.randint(0, 5)} started",
            f"[info] upstream server {self.fake.ipv4_private()}:{random.choice([8080, 8081, 3000])} weight={random.randint(1, 10)}",
        ]
        
        warning_templates = [
            f"[warn] {random.randint(1000, 65535)}#{random.randint(0, 100)}: *{random.randint(1, 999999)} upstream server temporarily disabled while connecting to upstream, client: {client_ip}",
            f"[warn] {random.randint(1000, 65535)}#{random.randint(0, 100)}: *{random.randint(1, 999999)} an upstream response is buffered to a temporary file /var/cache/nginx/proxy_temp/{random.randint(1, 99999)}/{random.randint(0, 99)}/{random.randint(0, 9999)}",
            f"[warn] SSL certificate verification is disabled",
            f"[warn] conflicting server name \"{self.fake.domain_name()}\" on 0.0.0.0:443, ignored",
        ]
        
        error_templates = [
            f"[error] {random.randint(1000, 65535)}#{random.randint(0, 100)}: *{random.randint(1, 999999)} connect() failed (111: Connection refused) while connecting to upstream, client: {client_ip}, server: {self.fake.domain_name()}, request: \"{method} {random.choice(paths)} HTTP/1.1\"",
            f"[error] {random.randint(1000, 65535)}#{random.randint(0, 100)}: *{random.randint(1, 999999)} upstream timed out (110: Connection timed out) while reading response header from upstream",
            f"[crit] {random.randint(1000, 65535)}#{random.randint(0, 100)}: *{random.randint(1, 999999)} SSL_do_handshake() failed (SSL: error:{random.randint(10000000, 99999999)}:SSL routines)",
            f"[error] {random.randint(1000, 65535)}#{random.randint(0, 100)}: *{random.randint(1, 999999)} open() \"/var/www/html{random.choice(paths)}\" failed (2: No such file or directory)",
            f"[error] {random.randint(1000, 65535)}#{random.randint(0, 100)}: *{random.randint(1, 999999)} recv() failed (104: Connection reset by peer)",
        ]
        
        templates = {
            'info': info_templates,
            'notice': info_templates,
            'debug': info_templates,
            'warning': warning_templates,
            'error': error_templates,
            'critical': error_templates,
            'alert': error_templates,
            'emergency': error_templates,
        }
        
        return {
            'priority': self._calculate_priority('local7', severity),
            'timestamp': self._get_timestamp(),
            'host': host,
            'app': random.choice(APPS['web_server']),
            'pid': random.randint(1000, 65535),
            'message': random.choice(templates.get(severity, info_templates)),
            'facility': 'local7',
            'severity': severity,
            'category': 'web_server',
            'metadata': {
                'client_ip': client_ip,
                'method': method,
                'status_code': status,
                'response_time_s': response_time,
                'bytes_sent': bytes_sent
            }
        }

