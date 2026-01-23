
# Syslog Generator

A comprehensive Python application for generating realistic syslog messages.
Perfect for testing Elasticsearch ingestion pipelines, Logstash configurations,
and Kibana dashboards.

## Features

- 📝 **Multiple Log Types**: Auth, network, application, system, security, database, web server
- 🎯 **Realistic Messages**: Uses Faker for realistic IPs, usernames, timestamps
- 📊 **Configurable Severity Distribution**: Control the mix of log levels
- 🚀 **Multiple Output Modes**: Console, UDP, TCP, File, Elasticsearch, or all simultaneously
- 🔌 **Elasticsearch Integration**: Direct indexing with bulk API, supports both data streams and classic indices
- 💥 **Burst Mode**: Simulates incidents (brute force, DDoS, outages)
- ⚡ **High Performance**: Capable of 1000+ messages/second
- 🎨 **Color-coded Console Output**: Easy visual identification of severity
- 📈 **Statistics Tracking**: Real-time and summary statistics
- 🔄 **DR Testing Support**: Test disaster recovery by writing to follower indices

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

#### Elasticsearch Configuration

Copy the template and configure your targets in `.env`:

```bash
cp .env.template .env
```

## Index Modes: Data Streams vs Classic Indices

The generator supports two indexing modes:

### Option 1: Data Streams (Recommended for Observability)

Use `INDEX_PREFIX`, `DATASET`, and `NAMESPACE` for data stream naming:

```bash
ES_PROD_INDEX_PREFIX=logs
ES_PROD_DATASET=syslog
ES_PROD_NAMESPACE=prod
# Results in: logs-syslog-prod
```

Data streams are ideal for time-series data with automatic rollover and ILM.

### Option 2: Classic Indices (For specific index names)

Use `INDEX` to write directly to a specific index name:

```bash
ES_PROD_INDEX=my-syslog-prod
# Results in: my-syslog-prod
```

Classic indices are useful for:
- Legacy systems expecting specific index names
- CCR (Cross-Cluster Replication) scenarios
- DR (Disaster Recovery) testing

> **Note**: If both `INDEX` and `INDEX_PREFIX` are specified, `INDEX` takes precedence.

## Example .env Configuration

```bash
# .env

# ============================================
# ACTIVE TARGET - Change this to switch!
# ============================================
ES_TARGET=PROD
ES_ENABLED=true

# ============================================
# DEV TARGET (Data Stream mode)
# ============================================
ES_DEV_URL=http://localhost:9200
ES_DEV_USERNAME=elastic
ES_DEV_PASSWORD=changeme
ES_DEV_INDEX_PREFIX=logs
ES_DEV_DATASET=syslog
ES_DEV_NAMESPACE=dev
ES_DEV_VERIFY_CERTS=false
ES_DEV_BATCH_SIZE=50

# ============================================
# STAGING TARGET (Classic Index mode - for DR testing)
# ============================================
ES_STAGING_URL=https://staging-cluster.es.cloud.es.io:9243
ES_STAGING_API_KEY=your-staging-api-key-here
ES_STAGING_INDEX=my-syslog-prod
ES_STAGING_VERIFY_CERTS=true
ES_STAGING_BATCH_SIZE=50

# ============================================
# PROD TARGET (Classic Index mode)
# ============================================
ES_PROD_URL=https://prod-cluster.es.cloud.es.io:9243
ES_PROD_API_KEY=your-prod-api-key-here
ES_PROD_INDEX=my-syslog-prod
ES_PROD_VERIFY_CERTS=true
ES_PROD_BATCH_SIZE=50

# ============================================
# GENERATOR SETTINGS
# ============================================
SYSLOG_RATE=10
SYSLOG_OUTPUT_MODE=both
```

## Disaster Recovery (DR) Testing

This generator can be used to test DR failover scenarios where you need to write to a replica cluster that was previously using CCR (Cross-Cluster Replication).

### Scenario

- **PROD**: Primary cluster with index `my-syslog-prod` (leader)
- **STAGING**: DR cluster with index `my-syslog-prod` (follower via CCR)

### DR Failover Steps

Before writing to a CCR follower index, you must **unfollow** it to promote it to a standalone writable index:

#### Option 1: Via Kibana UI

1. Go to **Stack Management** → **Cross-Cluster Replication**
2. Find your index in the **Follower indices** tab
3. Click on it → **Unfollow**

#### Option 2: Via Dev Tools / API

```json
# 1. Pause replication
POST /my-syslog-prod/_ccr/pause_follow

# 2. Close the index
POST /my-syslog-prod/_close

# 3. Unfollow (promotes to regular index)
POST /my-syslog-prod/_ccr/unfollow

# 4. Reopen the index
POST /my-syslog-prod/_open
```

#### Option 3: One-liner (if index can be closed)

```json
POST /my-syslog-prod/_ccr/pause_follow
POST /my-syslog-prod/_close
POST /my-syslog-prod/_ccr/unfollow
POST /my-syslog-prod/_open
```

### Test DR Writing

After unfollowing, switch to STAGING and start writing:

```bash
# Switch target
python switch_target.py -s STAGING

# Verify target
python switch_target.py -c

# Start generator
python -m syslog_generator.main
```

Expected output:
```
INFO - ✓ ES Target: STAGING -> https://staging-cluster:9243 -> my-syslog-prod
INFO - Connected to ES: xxxxx (v9.x.x)
```

### Common DR Error

If you see this error:
```
ERROR - 'status_exception', 'reason': 'a following engine does not accept operations without an assigned sequence number'
```

**Cause**: The index is still a CCR follower (read-only).

**Solution**: Run the unfollow steps above.

> ⚠️ **Important**: Once you unfollow, CCR replication is permanently broken for that index. To restore CCR, you must delete the index and recreate the follower from scratch.

## Switching Elasticsearch Targets

Use the `switch_target.py` script to manage and switch between different Elasticsearch environments.

### Quick Start

```bash
# Interactive mode
python switch_target.py

# List all configured targets
python switch_target.py --list

# Switch to a target
python switch_target.py --switch PROD

# Show current target
python switch_target.py --current

# Test connection
python switch_target.py --test
```

### Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--list` | `-l` | List all configured targets |
| `--switch TARGET` | `-s` | Switch to specified target |
| `--current` | `-c` | Show current active target |
| `--test [TARGET]` | `-t` | Test connection (current if not specified) |
| `--env-file PATH` | `-e` | Path to .env file (default: `.env`) |

### Supported Target Settings

| Setting | Description | Mode |
|---------|-------------|------|
| `URL` | Elasticsearch URL (required) | Both |
| `API_KEY` | API key authentication | Both |
| `USERNAME` | Basic auth username | Both |
| `PASSWORD` | Basic auth password | Both |
| `INDEX` | Direct index name | Classic |
| `INDEX_PREFIX` | Index name prefix | Data Stream |
| `DATASET` | Data stream dataset (default: `syslog`) | Data Stream |
| `NAMESPACE` | Data stream namespace (default: `default`) | Data Stream |
| `VERIFY_CERTS` | SSL certificate verification | Both |
| `CA_CERTS` | Path to CA certificate file | Both |
| `BATCH_SIZE` | Bulk indexing batch size | Both |
| `FLUSH_INTERVAL` | Flush interval in seconds | Both |

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
# Use Elasticsearch output (uses active target from .env)
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
        "names": ["logs*", "syslog*", "my-syslog-*"],
        "privileges": ["create_doc", "write", "create_index"]
      }
    ]
  }
}
```

### 2. Verify Data in Elasticsearch

```bash
# Check document count
curl -s "https://your-cluster:9243/my-syslog-prod/_count" \
  -H "Authorization: ApiKey YOUR_API_KEY"

# Search recent logs
curl -s "https://your-cluster:9243/my-syslog-prod/_search?size=5" \
  -H "Authorization: ApiKey YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"query": {"match_all": {}}, "sort": [{"@timestamp": "desc"}]}'
```

## Project Structure

```
syslog-generator/
├── config/
│   └── config.yaml           # Main configuration
├── syslog_generator/
│   ├── __init__.py
│   ├── main.py               # Entry point
│   ├── generator.py          # Log generation logic
│   ├── es_client.py          # Elasticsearch client
│   ├── outputs.py            # Output handlers
│   └── models.py             # Data models
├── logs/                     # Output directory for file mode
├── .env                      # Elasticsearch targets (from template)
├── .env.template             # Template for .env
├── switch_target.py          # Target switching utility
├── requirements.txt
└── README.md
```

## Requirements

```
faker>=18.0.0
pyyaml>=6.0
colorama>=0.4.6
elasticsearch>=8.0.0
python-dotenv>=1.0.0
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

### "a following engine does not accept operations"

**Cause**: Trying to write to a CCR follower index.

**Solution**: Unfollow the index first (see [DR Failover Steps](#dr-failover-steps)).

### Logs not appearing immediately in Kibana

- Reduce `ES_<TARGET>_BATCH_SIZE` in .env (e.g., 50)
- Reduce `ES_<TARGET>_FLUSH_INTERVAL` (e.g., 2 seconds)
- Data streams may have longer refresh intervals

### Connection errors

- Verify `ES_<TARGET>_URL` is correct (include port)
- Check `ES_<TARGET>_API_KEY` or credentials
- Ensure `ES_<TARGET>_VERIFY_CERTS=false` for self-signed certificates
- Test connection with: `python switch_target.py --test`

### Permission errors

- API key needs `create_doc` and `write` privileges on the index
- For data streams, ensure the data stream exists or user can create it

### Wrong index being used

Ensure your variable prefixes match your target:
```bash
ES_TARGET=STAGING
# ✅ Correct:
ES_STAGING_INDEX=my-syslog-prod
# ❌ Wrong:
ES_PROD_INDEX=my-syslog-prod  # Won't be read when target is STAGING
```

## License

MIT License
```
