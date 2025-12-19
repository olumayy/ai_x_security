# AI for the Win

### Build AI-Powered Security Tools | From Zero to Production

[![CI](https://github.com/depalmar/ai_for_the_win/actions/workflows/ci.yml/badge.svg)](https://github.com/depalmar/ai_for_the_win/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab01_phishing_classifier.ipynb)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)](./Dockerfile)

A comprehensive 24-week training program for security practitioners who want to build AI-powered tools for threat detection, incident response, and security automation.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│   Week 1-8          Week 9-16           Week 17-24                      │
│   ─────────         ──────────          ───────────                     │
│   ML Foundations    LLM & Agents        Production Systems              │
│                                                                         │
│   • Classification  • Prompt Eng        • Detection Pipelines           │
│   • Clustering      • RAG Systems       • IR Automation                 │
│   • Anomaly Det     • AI Agents         • Capstone Projects             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## What You'll Build

### Labs Overview

| Lab | Project | What You'll Learn |
|-----|---------|-------------------|
| **01** | **Phishing Classifier** | Text preprocessing, TF-IDF vectorization, Random Forest classification, model evaluation metrics |
| **02** | **Malware Clusterer** | Feature extraction from binaries, K-Means & DBSCAN clustering, dimensionality reduction, cluster analysis |
| **03** | **Anomaly Detector** | Statistical baselines, Isolation Forest, Local Outlier Factor, threshold optimization for security |
| **04** | **Log Analyzer** | Prompt engineering for security, structured output parsing, IOC extraction, LLM-powered analysis |
| **05** | **Threat Intel Agent** | ReAct pattern implementation, tool use with LangChain, autonomous investigation workflows |
| **06** | **Security RAG** | Document chunking, vector embeddings, ChromaDB, retrieval-augmented generation for Q&A |
| **07** | **YARA Generator** | Static malware analysis, pattern extraction, AI-assisted rule generation, rule validation |
| **08** | **Vuln Prioritizer** | CVSS scoring, risk-based prioritization, remediation planning with LLMs |
| **09** | **Detection Pipeline** | Multi-stage architectures, ML filtering, LLM enrichment, alert correlation |
| **10** | **IR Copilot** | Conversational agents, state management, playbook execution, incident documentation |
| **11** | **Ransomware Detector** | Entropy analysis, behavioral detection, ransom note IOC extraction, response automation |
| **12** | **Purple Team Sim** | Safe adversary emulation, detection validation, gap analysis, purple team exercises |

### Skills Progression

```
┌─────────────────────────────────────────────────────────────────────────┐
│  FOUNDATIONS          │  INTERMEDIATE           │  ADVANCED             │
│  Labs 01-03           │  Labs 04-07             │  Labs 08-12           │
├───────────────────────┼─────────────────────────┼───────────────────────┤
│  • Supervised ML      │  • Prompt Engineering   │  • System Design      │
│  • Unsupervised ML    │  • AI Agents            │  • Multi-stage ML+LLM │
│  • Feature Eng.       │  • RAG Systems          │  • Production IR      │
│  • Model Evaluation   │  • Code Generation      │  • Purple Teaming     │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/depalmar/ai_for_the_win.git
cd ai_for_the_win

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: .\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Set up API keys
cp .env.example .env
# Edit .env with your ANTHROPIC_API_KEY

# Run your first lab
cd labs/lab01-phishing-classifier
python solution/main.py
```

### Docker Quick Start

```bash
# Build and run with Docker Compose
docker-compose up dev

# Run tests in container
docker-compose run test

# Launch Jupyter notebooks
docker-compose up notebook
# Open http://localhost:8888
```

### Google Colab

Run labs directly in your browser - no setup required:

| Lab | Colab Link |
|-----|------------|
| Lab 01: Phishing Classifier | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab01_phishing_classifier.ipynb) |
| Lab 02: Malware Clustering | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab02_malware_clustering.ipynb) |
| Lab 03: Anomaly Detection | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab03_anomaly_detection.ipynb) |
| Lab 04: Log Analysis | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab04_llm_log_analysis.ipynb) |
| Lab 05: Threat Intel Agent | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab05_threat_intel_agent.ipynb) |
| Lab 06: Security RAG | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab06_security_rag.ipynb) |
| All 12 labs available | [Browse notebooks →](./notebooks/) |

---

## Repository Structure

```
ai_for_the_win/
├── labs/                          # 12 hands-on labs
│   ├── lab01-phishing-classifier/ # ML text classification
│   ├── lab02-malware-clustering/  # Unsupervised learning
│   ├── lab03-anomaly-detection/   # Network security
│   ├── lab04-llm-log-analysis/    # Prompt engineering
│   ├── lab05-threat-intel-agent/  # ReAct agents
│   ├── lab06-security-rag/        # Vector search + LLM
│   ├── lab07-yara-generator/      # AI code generation
│   ├── lab08-vuln-scanner-ai/     # Risk prioritization
│   ├── lab09-detection-pipeline/  # Multi-stage ML+LLM
│   ├── lab10-ir-copilot/          # Conversational IR
│   ├── lab11-ransomware-detection/# DFIR + behavioral analysis
│   └── lab12-ransomware-simulation/# Purple team exercises
├── notebooks/                     # Jupyter notebooks (Colab-ready)
├── capstone-projects/             # 4 comprehensive projects
├── templates/                     # Reusable code templates
│   ├── agents/                    # LangChain agent templates
│   ├── prompts/                   # Security prompt library
│   ├── visualizations/            # Dashboards & diagrams
│   └── reports/                   # Report generators
├── resources/                     # Tools, datasets, guides
├── setup/                         # Environment setup guides
│   └── guides/                    # Troubleshooting & error handling
├── tests/                         # Comprehensive test suite
├── Dockerfile                     # Multi-stage Docker build
└── docker-compose.yml             # Dev, test, notebook services
```

---

## Learning Paths

### Path 1: ML Foundations (Weeks 1-8)

Build core machine learning skills for security:

```
Lab 01 ──► Lab 02 ──► Lab 03
  │          │          │
  ▼          ▼          ▼
Text ML   Clustering  Anomaly
                      Detection
```

**Skills**: Supervised learning, unsupervised learning, feature engineering, model evaluation

### Path 2: LLM & Agents (Weeks 9-16)

Master LLMs for security applications:

```
Lab 04 ──► Lab 05 ──► Lab 06 ──► Lab 07
  │          │          │          │
  ▼          ▼          ▼          ▼
Prompts   Agents      RAG       Code Gen
```

**Skills**: Prompt engineering, ReAct agents, RAG systems, tool use

### Path 3: Production Systems (Weeks 17-24)

Build production-ready security systems:

```
Lab 08 ──► Lab 09 ──► Lab 10 ──► Capstone
  │          │          │          │
  ▼          ▼          ▼          ▼
Vuln Scan  Pipeline   IR Bot    Your Project
```

**Skills**: System design, multi-stage pipelines, conversational AI, deployment

---

## Lab Progress Tracker

Track your progress through the labs:

- [ ] **Lab 01**: Phishing Email Classifier
- [ ] **Lab 02**: Malware Sample Clustering
- [ ] **Lab 03**: Network Anomaly Detection
- [ ] **Lab 04**: LLM-Powered Log Analysis
- [ ] **Lab 05**: Threat Intelligence Agent
- [ ] **Lab 06**: Security RAG System
- [ ] **Lab 07**: AI YARA Rule Generator
- [ ] **Lab 08**: Vulnerability Scanner AI
- [ ] **Lab 09**: Threat Detection Pipeline
- [ ] **Lab 10**: IR Copilot Agent
- [ ] **Lab 11**: Ransomware Detection & Response
- [ ] **Lab 12**: Ransomware Simulation (Purple Team)
- [ ] **Capstone**: Complete one capstone project

---

## Technology Stack

| Category | Tools |
|----------|-------|
| **AI/ML** | Claude API, LangChain, scikit-learn, NumPy, Pandas |
| **Vector DB** | ChromaDB, embeddings |
| **Security** | YARA, Sigma, MITRE ATT&CK |
| **Development** | Python 3.9+, pytest, Docker, GitHub Actions |
| **Notebooks** | Jupyter, Google Colab |

---

## Capstone Projects

Choose one to demonstrate mastery:

| Project | Difficulty | Duration | Focus |
|---------|------------|----------|-------|
| **Security Analyst Copilot** | Advanced | 40-60 hrs | LLM agents, IR automation |
| **Automated Threat Hunter** | Advanced | 40-60 hrs | ML detection, pipelines |
| **Malware Analysis Assistant** | Intermediate | 30-40 hrs | Static analysis, YARA |
| **Vulnerability Intel Platform** | Intermediate | 30-40 hrs | RAG, prioritization |

Each project includes starter code, requirements, and evaluation criteria.

---

## Templates & Integrations

Jumpstart your projects with ready-to-use templates:

- **Agent Templates**: LangChain security agent, RAG agent
- **n8n Workflows**: IOC enrichment, alert triage with AI
- **SIEM Integrations**: Splunk, Elasticsearch, Microsoft Sentinel
- **Prompt Library**: Log analysis, threat detection, report generation

---

## Development

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific lab tests
pytest tests/test_lab01_phishing_classifier.py -v

# Run with coverage
pytest tests/ --cov=labs --cov-report=html

# Run in Docker
docker-compose run test
```

### Code Quality

```bash
# Format code
black .
isort .

# Lint
flake8 .

# Security scan
bandit -r labs/
```

### Environment Variables

Copy `.env.example` to `.env` and configure:

| Variable | Description | Required |
|----------|-------------|----------|
| `ANTHROPIC_API_KEY` | Claude API key | Yes (for LLM labs) |
| `VIRUSTOTAL_API_KEY` | VirusTotal API | Optional |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API | Optional |

---

## Getting Help

- **Troubleshooting**: Check the [troubleshooting guide](./setup/guides/troubleshooting-guide.md)
- **Error Handling**: See [error handling best practices](./setup/guides/error-handling-guide.md)
- **Documentation**: Browse [setup guides](./setup/) and [resources](./resources/)
- **Issues**: Open a [GitHub issue](https://github.com/depalmar/ai_for_the_win/issues)

---

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](./CONTRIBUTING.md) before submitting PRs.

Ways to contribute:
- Fix bugs or improve existing labs
- Add new sample data or test cases
- Improve documentation
- Share your capstone projects

---

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

---

## Disclaimer

This training material is intended for **educational purposes** and **authorized security testing only**. Users are responsible for ensuring compliance with all applicable laws and obtaining proper authorization before using any offensive techniques.

---

<p align="center">
  <b>Ready to build AI-powered security tools?</b><br>
  <a href="./labs/lab01-phishing-classifier/">Start with Lab 01</a> |
  <a href="./curriculum/ai-security-training-program.md">View Full Curriculum</a>
</p>
