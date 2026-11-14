# 🎤 3-Minute Hackathon Pitch Script
## Tech Fusion '26 — Problem Statement C: Orbit Security Incident Triage Assistant

---

### [Slide 1: Title & Hook — 0:00 to 0:30]
> *"Good day judges. Every SOC analyst faces the same nightmare: hundreds of alerts an hour, half of them false positives, and multi-source logs written across conflicting timezones. If an analyst makes a mistake, a breach occurs. If an AI assistant hallucinates a citation or misinterprets an approved maintenance window, audit compliance collapses.*  
> *Meet the **Orbit Incident Triage Assistant** — a zero-hallucination, deterministic-first triage and correlation engine built for Orbit Logistics."*

---

### [Slide 2: Architecture "Beyond a Single Prompt" — 0:30 to 1:00]
> *"A naive approach simply dumps logs into a massive LLM prompt and hopes for the best. That fails the leaderboard and fails production.*  
> *Our architecture operates in four distinct stages:*  
> 1. *First, our **Timezone Normalizer** unifies naive Pakistan Standard Time, UTC Z-tags, and line-level offsets into canonical UTC, adjusting internal firewall close-times and duration deltas.*  
> 2. *Second, our **Deterministic Pre-Flight Engine** checks incoming alerts against approved change records in `05_change_calendar.md`.*  
> 3. *Third, if an actual incident is confirmed, our **Context Packer** feeds indexed line slices into Google's state-of-the-art **Gemini 3.5 Flash** model with a strict 11-section schema.*  
> 4. *Finally, our **Citation Validator** ensures every single line cited matches physical lines inside the code fences before the analyst sees it."*

---

### [Slide 3: Live Demonstration Highlights — 1:00 to 2:15]
> *"Let's look at the live system in action:*  
> - *When an alert like ALT-9006 hits the queue — a vulnerability port scan — our deterministic engine flags it in under 10 milliseconds. It confirms scanner IP 10.10.9.50 and the scheduled window, auto-closing it as harmless with zero LLM API cost.*  
> - *When a true attack strikes — a phishing email leading to MFA fatigue and a 2.4 GB exfiltration — our system correlates events across email, VPN, and internal firewalls. It automatically assigns P1 severity and triggers the 15-minute SLA notification for CISO Hamza Qureshi.*  
> - *Notice our interactive dashboard: every claim has an interactive citation pill. One click slides open the exact raw log line from the ground truth files."*

---

### [Slide 4: Problem Understanding & Failure Cases — 2:15 to 2:45]
> *"What sets our solution apart is genuine problem understanding. We explicitly model environmental gaps:*  
> - *We detect the 57-minute internal firewall reboot window between 11:32 and 12:28 PKT and warn the analyst of coverage blindspots.*  
> - *We identify that SRV-FS01 and SRV-DB01 lack granular file and query auditing, citing file 20 rather than hallucinating file contents.*  
> - *And we resolve dynamic DHCP leases to prevent false IP attribution."*

---

### [Slide 5: Technical Excellence & Readiness — 2:45 to 3:00]
> *"70 unit tests passing, full Docker containerization, REST API and interactive 3D SOC frontend ready. The Orbit Incident Triage Assistant turns chaos into audit-proof clarity.*  
> *Thank you, and we welcome your questions!"*
