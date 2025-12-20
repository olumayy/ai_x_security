# AI Security Training - Learning Guide

A structured path from beginner to advanced AI-powered security tools.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        LEARNING PROGRESSION                                  │
│                                                                             │
│   BEGINNER          INTERMEDIATE           ADVANCED           EXPERT        │
│   ─────────         ────────────           ────────           ──────        │
│                                                                             │
│   Lab 01 ──────────► Lab 02 ──────────► Lab 08 ──────────► Lab 11          │
│   Phishing          Malware              Vuln Scanner        Ransomware     │
│   Classifier        Clustering           AI                  Detection      │
│        │                 │                    │                   │         │
│        ▼                 ▼                    ▼                   ▼         │
│   Lab 03 ──────────► Lab 04 ──────────► Lab 09 ──────────► Lab 12          │
│   Anomaly           LLM Log              Detection           Purple         │
│   Detection         Analysis             Pipeline            Team           │
│        │                 │                    │                             │
│        └────────────► Lab 06 ──────────► Lab 10                            │
│                       Security            IR Copilot                        │
│                       RAG                     │                             │
│                         │                     │                             │
│                         └──────► Lab 05 ◄─────┘                             │
│                                  Threat                                     │
│                                  Intel Agent                                │
│                                      │                                      │
│                                      ▼                                      │
│                                  Lab 07                                     │
│                                  YARA Gen                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Which Path Should I Take?

| Your Background | Start With | Estimated Time |
|-----------------|------------|----------------|
| New to ML/AI | Lab 01 → Lab 03 | 4-6 hours |
| Know ML, new to LLMs | Lab 04 → Lab 06 | 4-6 hours |
| Know LLMs, new to agents | Lab 05 → Lab 07 | 4-6 hours |
| Ready for production systems | Lab 08 → Lab 10 | 8-12 hours |
| Advanced DFIR focus | Lab 11 → Lab 12 | 8-10 hours |

---

## Labs by Difficulty

### 🟢 Beginner Labs (Start Here)

#### Lab 01: Phishing Email Classifier
**Difficulty:** ⭐ Easy | **Time:** 45-60 min | **Prerequisites:** Basic Python

**What You'll Learn:**
- Text preprocessing and feature extraction
- TF-IDF vectorization for text
- Random Forest classification
- Model evaluation metrics (precision, recall, F1)

**Key Concepts:**
```
Email Text → Preprocess → Extract Features → Train Model → Classify
     │            │              │               │            │
     ▼            ▼              ▼               ▼            ▼
 Raw text    Lowercase,     TF-IDF          Random      Phishing/
             remove HTML    vectors         Forest      Legitimate
```

**Why This Matters:**
Phishing remains the #1 attack vector. Understanding how ML classifies malicious content is foundational for security automation.

---

#### Lab 03: Network Anomaly Detection
**Difficulty:** ⭐ Easy | **Time:** 60-75 min | **Prerequisites:** Lab 01

**What You'll Learn:**
- Network flow feature engineering
- Isolation Forest for anomaly detection
- Threshold tuning and evaluation
- Autoencoder-based detection (optional)

**Key Concepts:**
```
Network Flows → Feature Engineering → Anomaly Score → Alert
      │                │                    │           │
      ▼                ▼                    ▼           ▼
  Packets,        bytes/sec,          Isolation     C2, DDoS,
  connections     port entropy         Forest       exfil detected
```

**Attack Types Detected:**
- C2 beaconing patterns
- Data exfiltration
- Port scanning
- DDoS indicators

---

### 🟡 Intermediate Labs

#### Lab 02: Malware Sample Clustering
**Difficulty:** ⭐⭐ Intermediate | **Time:** 60-75 min | **Prerequisites:** Lab 01

**What You'll Learn:**
- Feature engineering for malware analysis
- K-Means and DBSCAN clustering
- t-SNE/UMAP visualization
- Cluster interpretation

**Key Concepts:**
```
Malware Samples → Extract Features → Cluster → Visualize → Analyze
       │               │               │          │           │
       ▼               ▼               ▼          ▼           ▼
   PE files,       Imports,        K-Means    t-SNE      Family
   scripts        entropy,         DBSCAN     plots      groupings
                  strings
```

**Why Clustering?**
New malware variants are released constantly. Clustering helps identify families and track evolution without needing labels for every sample.

---

#### Lab 04: LLM-Powered Log Analysis
**Difficulty:** ⭐⭐ Intermediate | **Time:** 60-90 min | **Prerequisites:** API key

**What You'll Learn:**
- Prompt engineering for security
- Structured output parsing
- IOC extraction with LLMs
- MITRE ATT&CK mapping

**Key Concepts:**
```
┌─────────────────────────────────────────────────────────────┐
│                    LLM LOG ANALYSIS                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Raw Logs ──► System Prompt ──► LLM ──► Structured JSON    │
│                    │                         │              │
│                    ▼                         ▼              │
│            "You are a security       {                      │
│             log parser..."            "severity": 8,        │
│                                       "technique": "T1059", │
│                                       "iocs": [...]         │
│                                      }                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Prompt Engineering Tips:**
1. **Role Definition:** "You are a security analyst..."
2. **Output Format:** Explicitly define JSON schema
3. **Constraints:** "Return ONLY valid JSON"
4. **Context:** Include MITRE ATT&CK knowledge

---

#### Lab 06: Security RAG System
**Difficulty:** ⭐⭐ Intermediate | **Time:** 75-90 min | **Prerequisites:** Lab 04

**What You'll Learn:**
- Document chunking strategies
- Vector embeddings with ChromaDB
- Semantic search implementation
- Context-aware LLM responses

**Key Concepts:**
```
┌─────────────────────────────────────────────────────────────┐
│                    RAG ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Documents ──► Chunk ──► Embed ──► Store in Vector DB     │
│        │                              │                     │
│        │                              ▼                     │
│        │         Query ──► Embed ──► Similarity Search     │
│        │                              │                     │
│        │                              ▼                     │
│        └────────────► Context + Query ──► LLM ──► Answer   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Use Cases:**
- CVE lookup and analysis
- MITRE ATT&CK technique queries
- Security playbook recommendations
- Policy and compliance Q&A

---

#### Lab 07: AI YARA Rule Generator
**Difficulty:** ⭐⭐ Intermediate | **Time:** 60-75 min | **Prerequisites:** Lab 02, Lab 04

**What You'll Learn:**
- Binary analysis basics
- String and pattern extraction
- LLM-powered rule generation
- YARA syntax validation

**Key Concepts:**
```
Sample ──► Static Analysis ──► Extract Patterns ──► LLM ──► YARA Rule
   │             │                    │               │          │
   ▼             ▼                    ▼               ▼          ▼
 Binary      Strings,             Unique         Generate    Validated
             imports,            indicators       rule       detection
             sections                            syntax      rule
```

---

### 🟠 Advanced Labs

#### Lab 05: Threat Intelligence Agent
**Difficulty:** ⭐⭐⭐ Advanced | **Time:** 90-120 min | **Prerequisites:** Lab 04

**What You'll Learn:**
- ReAct agent pattern (Reasoning + Acting)
- Tool design for AI agents
- Memory systems (short-term, working)
- Multi-step autonomous reasoning

**Key Concepts:**
```
┌─────────────────────────────────────────────────────────────┐
│                    ReAct AGENT LOOP                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌──────────────────────────────────────────────────┐     │
│   │                                                  │     │
│   ▼                                                  │     │
│ THOUGHT ──► ACTION ──► OBSERVATION ──► (repeat) ────┘     │
│    │           │            │                              │
│    ▼           ▼            ▼                              │
│ "I need    ip_lookup    {"malicious":                      │
│  to check  ("1.2.3.4")   true, ...}                        │
│  this IP"                                                  │
│                              │                              │
│                              ▼                              │
│                        FINAL ANSWER                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Agent Tools:**
- `ip_lookup`: Check IP reputation
- `domain_analysis`: Analyze domains
- `hash_lookup`: Search malware databases
- `mitre_lookup`: Map to ATT&CK techniques

---

#### Lab 08: Vulnerability Scanner AI
**Difficulty:** ⭐⭐⭐ Advanced | **Time:** 90-120 min | **Prerequisites:** Lab 04, Lab 05

**What You'll Learn:**
- Vulnerability assessment automation
- CVSS scoring interpretation
- Risk-based prioritization
- AI-powered remediation planning

**Key Concepts:**
```
Assets ──► Scan ──► Vulns ──► AI Analysis ──► Prioritized Report
   │         │        │           │                │
   ▼         ▼        ▼           ▼                ▼
 Hosts,   Nuclei,   CVEs,    Business         Remediation
 apps     Nmap      misconf  context          roadmap
```

---

#### Lab 09: Threat Detection Pipeline
**Difficulty:** ⭐⭐⭐ Advanced | **Time:** 120-150 min | **Prerequisites:** Lab 03, Lab 04

**What You'll Learn:**
- Multi-stage detection architecture
- ML filtering with Isolation Forest
- LLM enrichment
- Event correlation

**Key Concepts:**
```
┌─────────────────────────────────────────────────────────────┐
│                 DETECTION PIPELINE                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Events ──► Normalize ──► ML Filter ──► LLM Enrich ──►     │
│                              │              │               │
│                              ▼              ▼               │
│                         Remove           Add ATT&CK,        │
│                         noise            context            │
│                                              │               │
│                                              ▼               │
│                              Correlate ──► Alert            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

#### Lab 10: IR Copilot Agent
**Difficulty:** ⭐⭐⭐ Advanced | **Time:** 120-150 min | **Prerequisites:** Lab 05, Lab 06

**What You'll Learn:**
- Conversational agent design
- Multi-tool orchestration
- State management
- Human-in-the-loop confirmation

**Key Concepts:**
```
Analyst ◄──► IR Copilot ◄──► Tools
   │              │            │
   ▼              ▼            ▼
"Investigate   Orchestrates  SIEM query,
 this alert"   workflow      IOC lookup,
               + confirms    containment
               actions
```

---

### 🔴 Expert Labs

#### Lab 11: Ransomware Detection & Response
**Difficulty:** ⭐⭐⭐⭐ Expert | **Time:** 4-5 hours | **Prerequisites:** Labs 04, 05, 09

**What You'll Learn:**
- Shannon entropy for encryption detection
- Behavioral ransomware detection
- Ransom note analysis with LLMs
- Automated response playbooks

**Key Concepts:**
```
┌─────────────────────────────────────────────────────────────┐
│              RANSOMWARE DETECTION SIGNALS                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  BEHAVIORAL                 STATIC                          │
│  ───────────               ────────                         │
│  • Mass file renames       • High entropy files             │
│  • Shadow copy deletion    • Ransom note patterns           │
│  • Process injection       • Known ransomware strings       │
│  • Rapid file access       • Suspicious extensions          │
│                                                             │
│  MITRE ATT&CK: T1486 (Encryption), T1490 (Inhibit Recovery)│
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Detection Formula:**
```
Threat Score = (Behavioral × 0.4) + (Entropy × 0.3) + (IOC × 0.3)
```

---

#### Lab 12: Purple Team Simulation
**Difficulty:** ⭐⭐⭐⭐ Expert | **Time:** 4-5 hours | **Prerequisites:** Lab 11

**What You'll Learn:**
- Purple team methodologies
- Safe adversary emulation
- Detection validation
- Gap analysis and improvement

**Key Concepts:**
```
┌─────────────────────────────────────────────────────────────┐
│                 PURPLE TEAM WORKFLOW                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   RED TEAM              COLLABORATION           BLUE TEAM   │
│   ────────              ─────────────           ─────────   │
│                                                             │
│   Emulate     ──────►   Joint Planning   ◄──────  Detect    │
│   TTPs                       │                   TTPs       │
│      │                       │                      │       │
│      │              Shared Exercise                 │       │
│      │                       │                      │       │
│      └──────────►  Gap Analysis  ◄──────────────────┘       │
│                          │                                  │
│                          ▼                                  │
│                    Improvements                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Core Technologies

### LLM Providers (Multi-Provider Support)

All LLM labs support multiple providers:

| Provider | Model | Best For | Environment Variable |
|----------|-------|----------|---------------------|
| **Anthropic** | Claude Sonnet | Reasoning, analysis | `ANTHROPIC_API_KEY` |
| **OpenAI** | GPT-4 Turbo | General purpose | `OPENAI_API_KEY` |
| **Google** | Gemini 1.5 Pro | Long context | `GOOGLE_API_KEY` |
| **Ollama** | Llama 3.1 | Local, free | (none) |

```python
# Usage examples:
llm = setup_llm(provider="anthropic")  # Use Claude
llm = setup_llm(provider="openai")     # Use GPT-4
llm = setup_llm(provider="gemini")     # Use Gemini
llm = setup_llm(provider="ollama")     # Use local Llama
```

### UI Frameworks

| Framework | Use Case | Labs |
|-----------|----------|------|
| **Gradio** | Quick demos, prototypes | All labs (demo/) |
| **Streamlit** | Dashboards | Lab 08, 09 |
| **FastAPI** | Production APIs | Lab 09, 10 |

### Workflow Orchestration

```python
# Simple workflow example with LangGraph
from langgraph.graph import StateGraph

workflow = StateGraph(DetectionState)
workflow.add_node("ingest", ingest_events)
workflow.add_node("filter", ml_filter)
workflow.add_node("enrich", llm_enrich)
workflow.add_node("correlate", correlate_events)
workflow.add_edge("ingest", "filter")
workflow.add_edge("filter", "enrich")
workflow.add_edge("enrich", "correlate")
```

---

## Recommended Learning Paths

### Path A: SOC Analyst Track (4 weeks)
Focus on detection and triage

```
Week 1: Lab 01, Lab 03
Week 2: Lab 04, Lab 06
Week 3: Lab 09
Week 4: Lab 10
```

### Path B: Threat Intel Track (4 weeks)
Focus on intelligence and hunting

```
Week 1: Lab 01, Lab 02
Week 2: Lab 04, Lab 05
Week 3: Lab 06, Lab 07
Week 4: Lab 08
```

### Path C: DFIR Track (4 weeks)
Focus on incident response and forensics

```
Week 1: Lab 03, Lab 04
Week 2: Lab 05, Lab 09
Week 3: Lab 11
Week 4: Lab 12
```

### Path D: Complete Program (8 weeks)
All labs in optimal order

```
Week 1-2: Lab 01, Lab 03, Lab 02
Week 3-4: Lab 04, Lab 06, Lab 07
Week 5-6: Lab 05, Lab 08, Lab 09
Week 7-8: Lab 10, Lab 11, Lab 12
```

---

## Assessment Checkpoints

After completing each section, you should be able to:

### After Beginner Labs
- [ ] Explain TF-IDF and why it works for text classification
- [ ] Build a binary classifier with scikit-learn
- [ ] Calculate precision, recall, and F1 score
- [ ] Describe Isolation Forest anomaly detection

### After Intermediate Labs
- [ ] Write effective security-focused prompts
- [ ] Parse LLM output into structured data
- [ ] Implement RAG with vector databases
- [ ] Extract and validate IOCs from text

### After Advanced Labs
- [ ] Design and implement AI agents with tools
- [ ] Build multi-stage detection pipelines
- [ ] Integrate LLMs with security workflows
- [ ] Create human-in-the-loop confirmation systems

### After Expert Labs
- [ ] Detect ransomware using behavioral and static analysis
- [ ] Plan and execute purple team exercises
- [ ] Generate detection rules from simulations
- [ ] Measure and improve detection coverage

---

## Getting Help

1. **Stuck on a lab?** Check the solution file and compare
2. **API errors?** Verify your `.env` file has correct keys
3. **Want to discuss?** Open a GitHub Discussion
4. **Found a bug?** Open an Issue with reproduction steps

---

## Next Steps After Completing Labs

1. **Build a Capstone Project** - See `capstone-projects/` for ideas
2. **Contribute** - Add new labs, improve existing ones
3. **Certify** - Document your learning for career advancement
4. **Apply** - Use these skills in your security practice

---

Happy Learning! 🛡️
