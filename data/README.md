# Sample Datasets

Sanitized, safe-to-use datasets for the AI Security Training Program labs.

```
data/
+-- README.md                 # This file
+-- phishing/                 # Email classification data
|   +-- emails.csv           # 500 phishing + legitimate emails
|   +-- urls.csv             # Malicious and benign URLs
+-- malware/                  # Malware metadata (no executables)
|   +-- samples.json         # PE file features and metadata
|   +-- family_labels.csv    # Malware family classifications
+-- logs/                     # Security log samples
|   +-- auth_logs.json       # Authentication events
|   +-- firewall_logs.csv    # Network firewall logs
|   +-- windows_events.json  # Windows Security events
+-- network/                  # Network traffic data
|   +-- traffic.csv          # Flow data with labels
|   +-- dns_queries.csv      # DNS query logs
|   +-- c2_beacons.json      # Simulated C2 beacon patterns
+-- threat-intel/             # Threat intelligence data
|   +-- iocs.json            # Indicators of Compromise
|   +-- attack_patterns.json # MITRE ATT&CK mapped attacks
|   +-- actor_profiles.json  # Threat actor TTPs
```

## Dataset Descriptions

### Phishing Data (`phishing/`)

| File | Records | Description |
|------|---------|-------------|
| `emails.csv` | 500 | Phishing and legitimate emails with labels |
| `urls.csv` | 1000 | URLs with malicious/benign classification |

**Columns in emails.csv:**
- `id`: Unique identifier
- `subject`: Email subject line
- `body`: Email body text
- `sender`: Sender address (anonymized)
- `label`: 0 = legitimate, 1 = phishing
- `confidence`: Label confidence score

### Malware Metadata (`malware/`)

| File | Records | Description |
|------|---------|-------------|
| `samples.json` | 200 | PE file features (no actual binaries) |
| `family_labels.csv` | 200 | Malware family classifications |

**Features in samples.json:**
- File entropy, section counts, import counts
- String patterns, API call frequencies
- Packer detection indicators
- Hash values (SHA256)

### Security Logs (`logs/`)

| File | Records | Description |
|------|---------|-------------|
| `auth_logs.json` | 5000 | Authentication events with anomalies |
| `firewall_logs.csv` | 10000 | Network firewall allow/deny logs |
| `windows_events.json` | 3000 | Windows Security Event Log entries |

### Network Data (`network/`)

| File | Records | Description |
|------|---------|-------------|
| `traffic.csv` | 10000 | NetFlow-style traffic records |
| `dns_queries.csv` | 5000 | DNS queries with DGA labels |
| `c2_beacons.json` | 500 | Simulated beacon patterns |

### Threat Intelligence (`threat-intel/`)

| File | Records | Description |
|------|---------|-------------|
| `iocs.json` | 1000 | IPs, domains, hashes with context |
| `attack_patterns.json` | 50 | Full attack chains with TTPs |
| `actor_profiles.json` | 20 | Threat actor profiles |

## Usage Examples

### Loading Phishing Emails

```python
import pandas as pd

# Load email dataset
emails = pd.read_csv('data/phishing/emails.csv')

# Split into features and labels
X = emails['body']
y = emails['label']

print(f"Total emails: {len(emails)}")
print(f"Phishing: {y.sum()}, Legitimate: {len(y) - y.sum()}")
```

### Loading Malware Features

```python
import json

# Load malware metadata
with open('data/malware/samples.json') as f:
    samples = json.load(f)

# Extract features for clustering
features = [
    [s['entropy'], s['section_count'], s['import_count']]
    for s in samples
]
```

### Loading Network Traffic

```python
import pandas as pd

# Load traffic data
traffic = pd.read_csv('data/network/traffic.csv')

# Filter for suspicious traffic
suspicious = traffic[traffic['label'] == 'malicious']
print(f"Suspicious flows: {len(suspicious)}")
```

### Loading Threat Intel

```python
import json

# Load IOCs
with open('data/threat-intel/iocs.json') as f:
    iocs = json.load(f)

# Get all malicious IPs
malicious_ips = [
    ioc['value'] for ioc in iocs
    if ioc['type'] == 'ip' and ioc['malicious']
]
```

## Data Generation

These datasets are synthetically generated for educational purposes. They are designed to:

1. **Be realistic** - Patterns mirror real-world security data
2. **Be safe** - No actual malware, credentials, or PII
3. **Be balanced** - Appropriate class distributions for ML
4. **Be documented** - Clear schemas and examples

### Regenerating Datasets

```bash
# Generate fresh datasets with different random seeds
python scripts/generate_datasets.py --seed 42

# Generate specific dataset types
python scripts/generate_datasets.py --type phishing --count 1000
python scripts/generate_datasets.py --type malware --count 500
```

## Lab Mapping

| Dataset | Used In Labs |
|---------|--------------|
| `phishing/emails.csv` | Lab 01 (Phishing Classifier) |
| `malware/samples.json` | Lab 02 (Malware Clustering), Lab 07 (YARA) |
| `logs/auth_logs.json` | Lab 03 (Anomaly), Lab 04 (Log Analysis), Lab 15 (Lateral Movement) |
| `network/traffic.csv` | Lab 03 (Anomaly), Lab 14 (C2 Traffic) |
| `threat-intel/iocs.json` | Lab 05 (Threat Intel), Lab 06 (RAG) |
| `threat-intel/actor_profiles.json` | Lab 16 (Actor Profiling) |

## License

These datasets are provided under the MIT License for educational use.
