# rapid7-mcp · Gemini SOC AI Assistant

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Streamlit](https://img.shields.io/badge/UI-Gemini%20Chat-purple)

An intelligent **NLP AI Chat Assistant** and unified MCP server for Rapid7 (**InsightIDR** and **InsightVM**). Designed with a modern **Google Gemini-style UI/UX**, it retains monthly security operations data and allows analysts, CISOs, and stakeholders to query any metric, incident, user risk, or SLA trend using natural language with **automatic interactive chart and graph generation**.

---

## ✨ Features

- **Google Gemini Chat UI/UX:** Clean, elegant dark aesthetic with Gemini sparkle branding, responsive prompt chips, metric KPI cards, and smooth markdown formatting.
- **Dynamic Charts & Graphs:** Every quantitative query dynamically renders interactive visualizations:
  - 📊 **Horizontal Bar Charts:** Top risky users ranked by UBA risk score.
  - ⏱️ **SLA Comparison Charts:** Achieved closure rates vs 90% SLA targets per priority level.
  - 🔍 **CVSS Distribution Breakdown:** Severity distribution across exploitable vulnerabilities.
  - 📈 **Multi-Month Investigation Trajectory:** 4-month historical volume and priority trends.
  - 🎯 **Attack Trends:** Frequency rankings of top triggered detection rules.
- **Retained Monthly SOC Telemetry:** High-fidelity retention of monthly SOC reports (including October 2026 for NAPSA / StarLabs SOC):
  - **Top Risky Users:** Chikwa Luputa, Chusi Mwanza, Priscilla Samakesa, James Phiri, Yvonne Admin, etc.
  - **SLA & MTTR:** Target vs actual closure rates, Mean Time to Resolution (2h 50m 47s), and pending closures.
  - **Incident Attribution:** Phishing / malicious link clicks (Office 365), administrator impersonation, and impossible travel.
  - **Event Source Health:** Real-time health, connection timeouts, and prescribed fixes for Active Directory WMI, SQL Server, and Cisco syslog.
  - **Vulnerability Management:** Total exploitable count (476,361), CVSSv3 breakdown, and top CVEs.
- **Seamless Rapid7 Connection:**
  - 1-click toggle between **Retained Monthly Archive** (instant zero-credential exploration) and **Live Rapid7 Insight Platform API**.
  - Built-in connection tester verifying API keys and platform regions in seconds.
  - Dual reasoning mode: Built-in local semantic NLP (offline & instant) or external LLMs (Google Gemini API, OpenAI, DeepSeek).

---

## 🚀 Quick Start

### 1. Launch the Gemini SOC Chat UI
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

### 2. Example Natural Language Questions to Ask
- *"Who were the top 5 risked users last month?"*
- *"Did we meet our SLAs for High and Medium priority incidents in October?"*
- *"Show exploitable vulnerabilities by CVSS score"*
- *"Which event sources currently have issues?"*
- *"Compare investigations over the last 4 months"*
- *"Which users clicked on malicious Office 365 links?"*
- *"What were the top 10 detection rules triggered?"*

---

## 🛡️ Architecture

```text
User (SOC Analyst / Manager / CISO)
       │ Plain Natural Language Query
       ▼
┌────────────────────────────────────────────────────────┐
│         Gemini SOC Chat Interface (app.py)             │
│  - Gemini Dark Surface & Sparkle Theme                 │
│  - Interactive Altair / Native Streamlit Charts        │
│  - Instant 1-Click Connection & Period Selector        │
└──────────────────────────┬─────────────────────────────┘
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
┌──────────────────────────┐  ┌──────────────────────────┐
│ Built-in SOC NLP Engine  │  │ LLM Agent (Gemini/OpenAI)│
│ (Offline, Zero-Config)   │  │ via Rapid7 MCP Tools     │
└────────────┬─────────────┘  └──────────┬───────────────┘
             │                           │
             └─────────────┬─────────────┘
                           ▼
┌────────────────────────────────────────────────────────┐
│             Rapid7 MCP Telemetry & Storage             │
│  • Retained Monthly Data Store (October 2026 NAPSA)   │
│  • Live Rapid7 InsightIDR REST APIs                    │
│  • Live Rapid7 InsightVM REST APIs                     │
└────────────────────────────────────────────────────────┘
```

---

## ⚙️ Configuration & Connection

Configure via the Streamlit sidebar or `.env`:

```env
# Rapid7 Live API (Optional — Retained mode works out-of-the-box)
IDR_REGION=us
IDR_API_KEY=your_insight_platform_api_key

# LLM API (Optional — Built-in engine works offline)
GEMINI_API_KEY=your_gemini_api_key
# or
OPENAI_API_KEY=your_openai_api_key
```

---

## 📄 License
MIT License.
