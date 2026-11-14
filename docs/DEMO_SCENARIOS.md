# 🎬 Orbit Incident Triage Assistant — Hackathon Demo Script & Walkthrough

> **Target Duration**: 2.5 – 3.0 Minutes  
> **Speaker**: Presenter / Team Member  
> **Screen**: Browser on `http://127.0.0.1:8000` (or live deployed URL)

---

## ⏱️ Video Timeline Breakdown

| Timecode | Section | Visual Focus on Screen | Key Talking Point |
|---|---|---|---|
| **0:00 - 0:35** | **The Problem & Hook** | Problem Statement slide / Homepage hero | Traditional LLMs hallucinate citations and choke on multi-source timezone offsets. Orbit SOC needs audit-proof truth. |
| **0:35 - 1:15** | **Architecture ("Beyond a Single Prompt")** | Architecture diagram in README / Code | 4-stage pipeline: Loader -> Timezone Normalizer -> Deterministic Pre-Flight -> Gemini 3.5 Flash + Citation Validator. |
| **1:15 - 1:50** | **Demo 1: Zero-Cost P4 Harmless Auto-Close** | UI: Click ALT-9006 in sidebar / alert dropdown | Watch instant 0ms latency classification of vulnerability scanner (10.10.9.50). Matched against `05_change_calendar.md:CHG-2026-1104-02`. Zero LLM tokens wasted. |
| **1:50 - 2:35** | **Demo 2: Full P1 Critical Attack Chain** | UI: Run Incident Triage for credential compromise & exfiltration | Show Timezone Swimlane (PKT to UTC), 11-section report, and click on citation pill `11_vpn_auth_log.md:13` to show sliding evidence drawer! |
| **2:35 - 3:00** | **Failure Cases & Rubric Conclusion** | Scroll to Missing Log Sources & DC Gap | Highlight awareness of internal firewall 57-min reboot gap and missing file auditing. Ready for production! |

---

## 🖱️ Step-by-Step Click Walkthrough for Video Recording

### Step 1: Open the Dashboard
- Open Chrome at `http://localhost:8000`.
- Point out the dark-mode SOC dashboard:
  - *"Welcome to the Orbit Incident Triage Assistant dashboard, designed specifically for Orbit Logistics SOC analysts."*

### Step 2: Show Instant Source Grounding
- Open the **Source Drawer** on the right side.
- Show that all 20 ground-truth files (`01` to `20`) are parsed and indexed with exact line numbers.
- Point out that line 1 is strictly the first line inside the code block.

### Step 3: Trigger Scenario A — Harmless False Positive Filter
- In the Alert / Query box, type or select:
  `Triage alert ALT-9006: Port scan detected from internal IP 10.10.9.50`
- Click **Analyze / Triage**.
- **What happens**:
  - The deterministic pre-flight check immediately intercepts the query.
  - Severity card turns to **P4 (Low)**.
  - Verdict: **Closed as harmless**.
  - Exact citation: `05_change_calendar.md:CHG-2026-1104-02`.
- **Say**:
  - *"Notice that our deterministic engine caught this in milliseconds without even calling an LLM. It verified the scanner IP, the target subnet, and the PKT time window against approved change records. This saves massive cloud costs and prevents alert fatigue."*

### Step 4: Trigger Scenario B — Multi-Source P1 Critical Attack
- In the Query box, type or paste:
  `Investigate suspicious VPN activity from Romania for user braza followed by SMB file transfer and credential alerts.`
- Click **Analyze / Triage**.
- **What happens**:
  1. **Severity Card**: Automatically flagged as **P1 (Critical)**.
  2. **Escalation SLA**: Highlights **CISO Hamza Qureshi (+92-300-5550001) within 15 minutes** (citing `04_escalation_and_contacts.md:ROW_CISO`).
  3. **Timezone Swimlane**: Shows events aligned to UTC, converting naive PKT firewall timestamps and offset web logs.
  4. **11-Section Audit Report**: Generates the full mandatory report from `01_company_security_rules.md`.
  5. **Click on a Citation Pill**: Click on `11_vpn_auth_log.md:8` or `11_vpn_auth_log.md:13`.
  6. **Evidence Drawer**: Slides in and instantly highlights the exact log line proving the 2.4 GB exfiltration!

### Step 5: Highlight Known Failure Cases & Limitations
- Point to **Section 8 (Missing log sources)** in the report:
  - *"Our assistant doesn't guess. It explicitly identifies that SRV-FS01 lacks file audit logging and flags the 57-minute internal firewall reboot window."*
- Wrap up:
  - *"100% reproducible, 70 passing unit tests, Dockerized, and production-ready."*
