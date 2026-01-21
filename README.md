

# Syslog Generator

A comprehensive Python application for generating realistic syslog messages.
Perfect for testing Elasticsearch ingestion pipelines, Logstash configurations,
and Kibana dashboards.

## Features

- 📝 **Multiple Log Types**: Auth, network, application, system, security, database, web server
- 🎯 **Realistic Messages**: Uses Faker for realistic IPs, usernames, timestamps
- 📊 **Configurable Severity Distribution**: Control the mix of log levels
- 🚀 **Multiple Output Modes**: Console, UDP, TCP, File, Elasticsearch, or all simultaneously
- 🔌 **Elasticsearch Integration**: Direct indexing with bulk API and data stream support
- 💥 **Burst Mode**: Simulates incidents (brute force, DDoS, outages)
- ⚡ **High Performance**: Capable of 1000+ messages/second
- 🎨 **Color-coded Console Output**: Easy visual identification of severity
- 📈 **Statistics Tracking**: Real-time and summary statistics

## Quick Start

### 1. Clone and Setup

```bash
# Clone or create the project directory
mkdir syslog-generator
cd syslog-generator

# Create virtual environment
python -m venv generator_venv

# Activate virtual environment
# On Windows:
generator_venv\Scripts\activate
# On macOS/Linux:
source generator_venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration

#### Main Configuration

Edit `config/config.yaml` for general settings:

```yaml
# config/config.yaml
generator:
  rate: 10                    # Messages per second
  burst_enabled: false
  burst_probability: 0.05
  burst_size_min: 10
  burst_size_max: 50

output:
  mode: both                  # console, file, udp, tcp, elasticsearch, both
  console:
    enabled: true
    colorize: true
  file:
    enabled: false
    path: ./logs/syslog.log
  elasticsearch:
    enabled: true
    target: prod              # References config/targets/prod.yaml

severity_distribution:
  emergency: 0.01
  alert: 0.02
  critical: 0.03
  error: 0.10
  warning: 0.15
  notice: 0.20
  info: 0.35
  debug: 0.14
```

#### Elasticsearch Target Configuration

Create target files in `config/targets/`:

```yaml
# config/targets/prod.yaml
url: https://your-elasticsearch-cluster.com:9243
api_key: your-api-key-here
index: logs                   # Index or data stream name
batch_size: 500               # Documents per bulk request
flush_interval: 5             # Seconds between flushes (even if batch not full)
verify_certs: true
```

```yaml
# config/targets/local.yaml
url: http://localhost:9200
username: elastic
password: changeme
index: syslog-logs
batch_size: 100
flush_interval: 5
verify_certs: false
```

## Usage

### Basic Examples

```bash
# Run with default config (console output)
python -m syslog_generator.main

# Run with custom rate
python -m syslog_generator.main --rate 100

# Generate specific number of messages
python -m syslog_generator.main --count 1000 --rate 50

# Run for specific duration (seconds)
python -m syslog_generator.main --duration 60 --rate 10

# Burst mode (simulates incidents)
python -m syslog_generator.main --burst
```

### Network Output

```bash
# Send to syslog server via UDP
python -m syslog_generator.main --mode udp --host 192.168.1.100 --port 514

# Send via TCP
python -m syslog_generator.main --mode tcp --host 192.168.1.100 --port 514
```

### File Output

```bash
# Write to file
python -m syslog_generator.main --mode file --file ./logs/syslog.log
```

### Elasticsearch Output

```bash
# Use Elasticsearch output (uses config/targets/prod.yaml)
python -m syslog_generator.main --mode elasticsearch

# Both console and Elasticsearch
python -m syslog_generator.main --mode both

# High-volume test to Elasticsearch
python -m syslog_generator.main --mode elasticsearch --rate 100 --count 10000
```

## Elasticsearch Setup

### 1. Create API Key (Elastic Cloud)

In Kibana → Stack Management → API Keys → Create API Key:

- Name: `syslog-generator`
- Restrict privileges (optional):

```json
{
  "syslog": {
    "cluster": ["monitor"],
    "indices": [
      {
        "names": ["logs*", "syslog*"],
        "privileges": ["create_doc", "write", "create_index"]
      }
    ]
  }
}
```

### 2. Data Streams

The generator ingest Elasticsearch data through [WIRED streams](https://www.elastic.co/docs/solutions/observability/streams/wired-streams). When using a data stream (like `logs`), the generator automatically uses the `create` operation for indexing.

### 3. Verify Data in Elasticsearch

```bash
# Check document count
curl -s "https://your-cluster:9243/logs/_count" \
  -H "Authorization: ApiKey YOUR_API_KEY"

# Search recent logs
curl -s "https://your-cluster:9243/logs/_search?size=5" \
  -H "Authorization: ApiKey YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"query": {"match_all": {}}, "sort": [{"@timestamp": "desc"}]}'
```

## Project Structure

```
syslog-generator/
├── config/
│   ├── config.yaml           # Main configuration
│   └── targets/
│       ├── prod.yaml         # Production ES target
│       └── local.yaml        # Local ES target
├── syslog_generator/
│   ├── __init__.py
│   ├── main.py               # Entry point
│   ├── generator.py          # Log generation logic
│   ├── es_client.py          # Elasticsearch client
│   ├── outputs.py            # Output handlers
│   └── models.py             # Data models
├── logs/                     # Output directory for file mode
├── requirements.txt
└── README.md
```

## Requirements

```
faker>=18.0.0
pyyaml>=6.0
colorama>=0.4.6
elasticsearch>=8.0.0
```

## Performance Tuning

| Setting | Low Volume | High Volume |
|---------|------------|-------------|
| `rate` | 1-10 | 100-1000+ |
| `batch_size` | 50-100 | 500-1000 |
| `flush_interval` | 5-10s | 1-2s |

For high-volume testing:

```bash
python -m syslog_generator.main --rate 500 --count 100000 --mode elasticsearch
```

## Troubleshooting

### Logs not appearing immediately in Kibana

- Reduce `batch_size` in target config (e.g., 50)
- Reduce `flush_interval` (e.g., 2 seconds)
- Data streams may have longer refresh intervals

### Connection errors

- Verify `url` is correct (include port)
- Check `api_key` or credentials
- Ensure `verify_certs: false` for self-signed certificates

### Permission errors

- API key needs `create_doc` and `write` privileges on the index
- For data streams, ensure the data stream exists or user can create it

## License

MIT License
```
