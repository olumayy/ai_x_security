# Lab 00b: Machine Learning Concepts for Security

Understand machine learning fundamentals before writing code. This lab explains **what** ML does and **why** it works, using security examples.

## Learning Objectives

By the end of this lab, you will understand:
1. What machine learning is (and isn't)
2. Types of ML: supervised, unsupervised, reinforcement
3. How models learn from data
4. Key concepts: features, labels, training, evaluation
5. When to use ML for security problems

## Estimated Time

1-2 hours (reading and exercises)

## Prerequisites

- Curiosity about how AI works
- Basic math (no calculus required)

---

## Part 1: What Is Machine Learning?

### Traditional Programming vs Machine Learning

```
TRADITIONAL PROGRAMMING:
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Rules     │ +   │   Data      │ ──► │   Output    │
│ (you write) │     │ (input)     │     │ (results)   │
└─────────────┘     └─────────────┘     └─────────────┘

Example: IF email contains "click here to claim" THEN spam

MACHINE LEARNING:
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Data      │ +   │   Output    │ ──► │   Rules     │
│ (examples)  │     │ (labels)    │     │ (learned)   │
└─────────────┘     └─────────────┘     └─────────────┘

Example: Given 10,000 emails labeled spam/not-spam, learn the patterns
```

### Why Use ML for Security?

| Challenge | Traditional Approach | ML Approach |
|-----------|---------------------|-------------|
| Phishing detection | Keyword lists, regex rules | Learn patterns from examples |
| Malware families | Signature matching | Cluster by behavior |
| Anomaly detection | Static thresholds | Learn "normal" baseline |
| Threat intel | Manual analysis | Pattern recognition at scale |

**ML shines when:**
- Rules are too complex to write manually
- Patterns change over time (adversaries adapt)
- You have lots of labeled examples
- You need to find unknown threats

**ML struggles when:**
- You have very little data
- You need 100% explainability
- The problem is simple (use rules instead)
- Adversaries can easily evade the model

---

## Part 2: Types of Machine Learning

### 2.1 Supervised Learning

**Definition:** Learn from labeled examples to predict labels for new data.

```
Training Data:
┌─────────────────────────────────────┬───────────┐
│ Email Content                       │ Label     │
├─────────────────────────────────────┼───────────┤
│ "Meeting at 3pm tomorrow"           │ NOT SPAM  │
│ "Congratulations! You won $1M"      │ SPAM      │
│ "Project update attached"           │ NOT SPAM  │
│ "Click here to claim your prize"    │ SPAM      │
└─────────────────────────────────────┴───────────┘

After Training:
┌─────────────────────────────────────┐
│ "Urgent: Verify your account now"   │ ──► SPAM (predicted)
└─────────────────────────────────────┘
```

**Security Examples:**
- **Classification:** Is this email phishing? (Yes/No)
- **Classification:** What malware family is this sample? (Emotet/Ryuk/Other)
- **Regression:** What's the risk score? (0-100)

**Key Algorithms:**
- Random Forest (decision trees combined)
- Logistic Regression (for probabilities)
- Support Vector Machines (find boundaries)
- Neural Networks (learn complex patterns)

### 2.2 Unsupervised Learning

**Definition:** Find patterns in data without labels.

```
Input Data (no labels):
┌─────────────────────────────────────┐
│ Malware Sample A: imports X, Y, Z   │
│ Malware Sample B: imports X, Y, W   │
│ Malware Sample C: imports A, B, C   │
│ Malware Sample D: imports A, B, D   │
└─────────────────────────────────────┘

After Clustering:
┌─────────────────────────┐  ┌─────────────────────────┐
│ Cluster 1: A, B         │  │ Cluster 2: C, D         │
│ (similar imports X,Y)   │  │ (similar imports A,B)   │
└─────────────────────────┘  └─────────────────────────┘
```

**Security Examples:**
- **Clustering:** Group similar malware samples
- **Anomaly Detection:** Find unusual network traffic
- **Dimensionality Reduction:** Visualize threat landscape

**Key Algorithms:**
- K-Means (group into K clusters)
- DBSCAN (density-based clustering)
- Isolation Forest (anomaly detection)
- t-SNE/UMAP (visualization)

### 2.3 Reinforcement Learning

**Definition:** Learn by trial and error with rewards/penalties.

```
┌─────────┐    action    ┌─────────────┐
│  Agent  │ ──────────►  │ Environment │
│         │ ◄────────── │             │
└─────────┘    reward    └─────────────┘
```

**Security Examples:**
- Automated penetration testing
- Adaptive defense systems
- Game-theoretic security

*(Less common in security - we focus on supervised/unsupervised)*

---

## Part 3: Key ML Concepts

### 3.1 Features

**Features** are the inputs to your model - the measurable properties of your data.

```
EMAIL FEATURES:
┌────────────────────────────────────────────────────────┐
│ Feature                │ Value    │ Type              │
├────────────────────────┼──────────┼───────────────────┤
│ word_count             │ 150      │ Numeric           │
│ has_attachment         │ True     │ Boolean           │
│ sender_domain          │ gmail    │ Categorical       │
│ urgent_words_count     │ 3        │ Numeric           │
│ link_count             │ 5        │ Numeric           │
│ sent_hour              │ 3 (AM)   │ Numeric           │
└────────────────────────────────────────────────────────┘
```

**Good features for security:**
- Network: bytes sent, packet count, port numbers, timing
- Malware: file size, entropy, imports, strings
- Logs: event type, timestamp, user, source IP
- Email: sender, subject keywords, attachment type

**Feature Engineering** = creating useful features from raw data. This is often the most important part of ML!

### 3.2 Labels

**Labels** are the answers you want to predict (supervised learning only).

```
CLASSIFICATION LABELS:
- Binary: spam/not-spam, malicious/benign, attack/normal
- Multi-class: malware family (Emotet, Ryuk, TrickBot, Other)

REGRESSION LABELS:
- Continuous: risk score (0-100), time to detection (seconds)
```

**Getting labels is hard!** Common approaches:
- Manual labeling by analysts
- Using threat intel feeds
- Crowdsourcing
- Weak supervision (heuristics)

### 3.3 Training, Validation, and Testing

```
YOUR DATA
┌────────────────────────────────────────────────────────┐
│                                                        │
│  ┌──────────────┐  ┌────────────┐  ┌────────────────┐ │
│  │   TRAINING   │  │ VALIDATION │  │     TEST       │ │
│  │    (70%)     │  │   (15%)    │  │    (15%)       │ │
│  │              │  │            │  │                │ │
│  │ Model learns │  │ Tune model │  │ Final score    │ │
│  │ from this    │  │ parameters │  │ (don't touch!) │ │
│  └──────────────┘  └────────────┘  └────────────────┘ │
│                                                        │
└────────────────────────────────────────────────────────┘
```

**Why split the data?**
- Training: Model learns patterns
- Validation: Tune hyperparameters, avoid overfitting
- Test: Unbiased final evaluation

**Never train on test data!** That's cheating.

### 3.4 Overfitting vs Underfitting

```
UNDERFITTING                GOOD FIT                 OVERFITTING
(too simple)               (just right)             (too complex)

    ○ ○                        ○ ○                      ○ ○
  ○     ○                    ○     ○                  ○     ○
────────────               ╭───────╮               ╭~╮ ╭~╮ ╭~╮
  ●     ●                    ●     ●               ╰●╯ ╰●╯ ╰●╯
    ● ●                        ● ●                    ● ●

Model too simple         Model captures           Model memorizes
to capture pattern       the real pattern         noise in training data
```

**Signs of overfitting:**
- Perfect accuracy on training data
- Poor accuracy on test data
- Model is too complex for the data

**How to prevent overfitting:**
- Get more training data
- Use simpler models
- Regularization (penalize complexity)
- Cross-validation

### 3.5 Evaluation Metrics

#### For Classification:

```
                    PREDICTED
                 Positive  Negative
              ┌──────────┬──────────┐
    Positive  │    TP    │    FN    │  ← Actual positives
ACTUAL        ├──────────┼──────────┤
    Negative  │    FP    │    TN    │  ← Actual negatives
              └──────────┴──────────┘
                  ↑           ↑
            Predicted    Predicted
            positives    negatives
```

| Metric | Formula | What it means | Security context |
|--------|---------|---------------|------------------|
| **Accuracy** | (TP+TN)/Total | % correct overall | Can be misleading with imbalanced data |
| **Precision** | TP/(TP+FP) | % of positive predictions that are correct | "Of alerts raised, how many are real?" |
| **Recall** | TP/(TP+FN) | % of actual positives found | "Of real attacks, how many did we catch?" |
| **F1 Score** | 2×(P×R)/(P+R) | Balance of precision and recall | Good single metric |

**Security trade-off:**
- High **Precision** = fewer false alarms, but might miss attacks
- High **Recall** = catch more attacks, but more false alarms
- SOC analysts often prefer high precision (alert fatigue is real)
- Critical systems might prefer high recall (can't miss attacks)

#### For Anomaly Detection:

```
Normal data distribution:
                 ┌─────────────────┐
                 │    ████████     │  ← Normal behavior
                 │  ██████████████ │
                 │████████████████ │
                 └─────────────────┘
                        │
Threshold ──────────────┼──────────────
                        │
                 ○      │      ○       ← Anomalies (outliers)
```

Key metrics:
- **True Positive Rate** (TPR): % of anomalies detected
- **False Positive Rate** (FPR): % of normal flagged as anomaly
- **AUC-ROC**: Area under ROC curve (0.5 = random, 1.0 = perfect)

---

## Part 4: The ML Workflow

### Step-by-Step Process

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         ML WORKFLOW                                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. DEFINE PROBLEM          2. COLLECT DATA         3. EXPLORE DATA     │
│  ┌──────────────┐          ┌──────────────┐        ┌──────────────┐     │
│  │ What are you │          │ Get labeled  │        │ Visualize,   │     │
│  │ trying to    │    ───►  │ examples     │  ───►  │ understand   │     │
│  │ predict?     │          │ (lots!)      │        │ distributions│     │
│  └──────────────┘          └──────────────┘        └──────────────┘     │
│                                                           │              │
│                                                           ▼              │
│  6. DEPLOY & MONITOR       5. EVALUATE              4. BUILD MODEL      │
│  ┌──────────────┐          ┌──────────────┐        ┌──────────────┐     │
│  │ Put in       │          │ Test on held │        │ Select algo, │     │
│  │ production,  │   ◄───   │ out data,    │  ◄───  │ engineer     │     │
│  │ monitor drift│          │ check metrics│        │ features     │     │
│  └──────────────┘          └──────────────┘        └──────────────┘     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Example: Building a Phishing Classifier

**1. Define Problem:**
- Goal: Detect phishing emails
- Type: Binary classification
- Success metric: F1 score > 0.90

**2. Collect Data:**
- 50,000 emails labeled as phishing/legitimate
- Sources: company email, public datasets
- Balance: ~10% phishing, ~90% legitimate

**3. Explore Data:**
- What words appear in phishing vs legitimate?
- What domains send phishing?
- Time patterns?

**4. Build Model:**
- Features: word frequencies (TF-IDF), sender domain, urgency words
- Algorithm: Random Forest
- Hyperparameters: 100 trees, max depth 10

**5. Evaluate:**
- Test accuracy: 95%
- Precision: 0.88 (12% of alerts are false positives)
- Recall: 0.92 (caught 92% of phishing)
- F1: 0.90 ✓

**6. Deploy:**
- Integrate with email gateway
- Monitor for drift (new phishing tactics)
- Retrain monthly

---

## Part 5: Common Pitfalls

### 1. Data Leakage
**Problem:** Information from the future or test set leaks into training.

```
BAD: Using "is_blocked" feature to predict if we should block
     (the answer is in the input!)

BAD: Training on data that includes test samples
```

### 2. Class Imbalance
**Problem:** One class dominates (99% normal, 1% attacks).

```
BAD: Model predicts "normal" for everything → 99% accuracy!
     But catches 0% of attacks.

SOLUTIONS:
- Oversample minority class (SMOTE)
- Undersample majority class
- Use class weights
- Focus on precision/recall, not accuracy
```

### 3. Concept Drift
**Problem:** Patterns change over time.

```
Model trained on 2023 data
           │
           ▼
Attackers change tactics in 2024
           │
           ▼
Model performance degrades
           │
           ▼
Need to retrain with new data
```

### 4. Adversarial Examples
**Problem:** Attackers craft inputs to fool the model.

```
Original malware → Detected (98% confidence)
           │
           ▼
Add benign strings, pad file, change metadata
           │
           ▼
Modified malware → Not detected (20% confidence)
```

---

## Part 6: ML for Security - Decision Guide

### When to Use ML

| Situation | Use ML? | Why |
|-----------|---------|-----|
| Known malware signatures | No | Use signature matching |
| New/unknown malware variants | Yes | ML can generalize |
| Simple threshold rules | No | Just use rules |
| Complex multi-feature patterns | Yes | Too complex for rules |
| You have 100 samples | Maybe | Might not be enough |
| You have 100,000 samples | Yes | Plenty of data |
| 100% explainability required | Maybe | Use interpretable models |
| Speed is critical (< 1ms) | Maybe | Some models are slow |

### Algorithm Selection

```
START
  │
  ▼
Do you have labels? ──No──► UNSUPERVISED
  │                         ├─ Clustering (K-Means, DBSCAN)
  Yes                       └─ Anomaly Detection (Isolation Forest)
  │
  ▼
What type of output?
  │
  ├─ Categories ──► CLASSIFICATION
  │                 ├─ Simple: Logistic Regression
  │                 ├─ Robust: Random Forest
  │                 └─ Complex: Neural Network
  │
  └─ Numbers ────► REGRESSION
                   ├─ Simple: Linear Regression
                   ├─ Robust: Random Forest Regressor
                   └─ Complex: Neural Network
```

---

## Exercises

### Exercise 1: Feature Brainstorm
For each security problem, list 5 features you would extract:
1. Detecting malicious PowerShell commands
2. Identifying C2 beacon traffic
3. Classifying malware by family

### Exercise 2: Metric Selection
Which metric would you prioritize and why?
1. Ransomware detection system for hospitals
2. Spam filter for personal email
3. Anomaly detection for low-priority logs

### Exercise 3: Identify the Pitfall
What's wrong with each approach?
1. Training a phishing detector using emails from one week only
2. Using the email subject line to predict if an email is "already reported as phishing"
3. Testing your model on the same data you trained on

---

## What's Next?

You now understand the concepts! Time to code:

- **Lab 01**: Phishing Classifier - Build your first ML security tool
- **Lab 02**: Malware Clustering - Unsupervised learning in practice
- **Lab 03**: Anomaly Detection - Find the needle in the haystack

---

## Glossary

| Term | Definition |
|------|------------|
| **Algorithm** | The mathematical method used to learn patterns |
| **Classification** | Predicting categories (spam/not spam) |
| **Clustering** | Grouping similar items without labels |
| **Feature** | A measurable property of your data |
| **Hyperparameter** | Settings you choose before training (e.g., number of trees) |
| **Label** | The answer you're trying to predict |
| **Model** | The learned rules/patterns from training |
| **Overfitting** | Model memorizes training data, fails on new data |
| **Regression** | Predicting continuous numbers (risk score) |
| **Supervised** | Learning with labeled examples |
| **Training** | The process of learning from data |
| **Unsupervised** | Learning without labels (find patterns) |

---

## Resources

- [Google ML Crash Course](https://developers.google.com/machine-learning/crash-course) - Free, excellent intro
- [Scikit-learn Tutorials](https://scikit-learn.org/stable/tutorial/) - Hands-on Python ML
- [MITRE ATLAS](https://atlas.mitre.org/) - Adversarial ML threats
- [Malware Data Science Book](https://nostarch.com/malwaredatascience) - Security-focused ML
