# Syslog Generator

A comprehensive Python application for generating realistic syslog messages.
Perfect for testing Elasticsearch ingestion pipelines, Logstash configurations,
and Kibana dashboards.

## Features

- 📝 **Multiple Log Types**: Auth, network, application, system, security, database, web server
- 🎯 **Realistic Messages**: Uses Faker for realistic IPs, usernames, timestamps
- 📊 **Configurable Severity Distribution**: Control the mix of log levels
- 🚀 **Multiple Output Modes**: Console, UDP, TCP, File, or all simultaneously
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
venv\Scripts\activate
# On macOS/Linux:
source generator_venv/bin/activate

# Install dependencies
pip install -r requirements.txt


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
