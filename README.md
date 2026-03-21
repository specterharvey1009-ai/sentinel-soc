# 🛡 SENTINEL SOC Assistant

A cybersecurity SOC (Security Operations Center) assistant that connects to your EDR platform, fetches real alerts, maps them to MITRE ATT&CK, and provides AI-powered investigation guidance — all without needing an external AI API key.

![SENTINEL SOC](https://img.shields.io/badge/SENTINEL-SOC%20Assistant-00e5ff?style=for-the-badge&logo=shield&logoColor=black)
![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-339933?style=for-the-badge&logo=node.js&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

---

## ✨ Features

- **Real EDR Integration** — connects to CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint, and VMware Carbon Black
- **7-Day Alert History** — fetches and continuously monitors alerts from the past week (configurable)
- **MITRE ATT&CK Mapping** — automatically maps every alert to relevant techniques and tactics
- **AI-Powered Analysis** — step-by-step investigation guidance, attack chain context, and IOC blocking recommendations
- **Multi-Source Threat Intelligence Chat** — searches MITRE ATT&CK, NIST NVD (live CVE data), and CISA KEV catalog
- **Report Generation** — generate Weekly, Incident, Executive, or MITRE Coverage reports
- **5 Download Formats** — HTML, Markdown, Plain Text, CSV, JSON
- **No External AI API Key Required** — built-in threat analysis engine runs entirely via the local proxy

---

## 🗂 Project Structure

```
sentinel-soc/
├── sentinel_soc.html      # Main dashboard UI (open in browser)
├── sentinel_proxy.js      # Local proxy server (handles CORS + AI analysis)
├── package.json           # Node.js dependencies
├── .gitignore
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites
- [Node.js](https://nodejs.org/) v18 or higher
- A supported EDR platform **or** use Demo Mode (no credentials needed)

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/sentinel-soc.git
cd sentinel-soc
```

### 2. Install dependencies
```bash
npm install
```

### 3. Start the proxy server
```bash
node sentinel_proxy.js
```

You should see:
```
✅ SENTINEL Proxy running on http://localhost:3847
✅ No API key needed — using built-in threat analysis engine.

   Open sentinel_soc.html in your browser.
```

### 4. Open the dashboard
Open `sentinel_soc.html` directly in your browser (double-click or drag into Chrome/Firefox/Edge).

The topbar will show **🟢 Proxy: Running** when the proxy is detected.

---

## 🔌 EDR Platform Setup

### Demo Mode
Select **Demo Mode** — no credentials needed. Loads 12 realistic pre-built alerts spanning 7 days.

### CrowdStrike Falcon
1. Go to **Falcon Console → Support → API Clients and Keys**
2. Create a new API client with scopes: `Detections:READ`, `Hosts:READ`
3. Copy the **Client ID** and **Client Secret**
4. Enter both in SENTINEL and click **Test Connection**

### SentinelOne
1. Log in to your SentinelOne management console
2. Click your **username → My User → API Token → Generate**
3. Copy the full token (shown only once)
4. Enter the token + your management URL (e.g. `https://usea1.sentinelone.net`)

### Microsoft Defender for Endpoint
1. Go to **Azure Portal → App Registrations → New Registration**
2. Under **API Permissions**, add `WindowsDefenderATP` → `Alert.Read.All`, `Machine.Read.All`
3. Create a **Client Secret** under Certificates & Secrets
4. Enter Tenant ID, Client (App) ID, and Client Secret in SENTINEL

### VMware Carbon Black
1. Go to **CB Cloud Console → Settings → API Access**
2. Create an API key with `org.alerts:READ` and `org.devices:READ` permissions
3. Copy the **Org Key**, **API ID**, and **API Secret**

---

## 💬 Chat Capabilities

The SENTINEL AI Chat searches multiple sources to answer your questions:

| Source | What it covers |
|--------|----------------|
| MITRE ATT&CK Knowledge Base | 20+ technique deep-dives with detection commands |
| NIST NVD API (live) | CVE details, CVSS scores — try `"CVE-2024-21413"` |
| CISA KEV Catalog (live) | Known exploited vulnerabilities with patch deadlines |
| Built-in SOC Playbooks | Ransomware, phishing, C2, lateral movement, IR procedures |

**Example questions:**
- `"What is Kerberoasting and how do I detect it?"`
- `"CVE-2024-21413"` — pulls live NVD data
- `"How do I respond to a ransomware incident?"`
- `"Explain T1003.001"`
- `"What MITRE techniques does Lazarus Group use?"`
- `"How do I hunt for Cobalt Strike beacons?"`

---

## 📄 Report Formats

| Format | Best for |
|--------|----------|
| HTML | Sharing with management, email attachments |
| Markdown | Documentation, GitHub wikis |
| Plain Text | Ticketing systems (Jira, ServiceNow) |
| CSV | Excel analysis, pivot tables |
| JSON | API integrations, SIEM ingestion |

---

## 🔒 Security Notes

- **Credentials never leave your machine** — all EDR API calls are made server-side by the proxy, not from the browser
- **No data is sent to any cloud service** — the proxy runs entirely locally
- **Add your own API key** (optional) — if you have an Anthropic API key, set it as an environment variable for Claude-powered analysis:
  ```bash
  ANTHROPIC_API_KEY=sk-ant-... node sentinel_proxy.js
  ```

---

## 🛠 Troubleshooting

| Problem | Fix |
|---------|-----|
| `Proxy: Offline` in topbar | Run `node sentinel_proxy.js` first |
| `SyntaxError` on startup | Ensure Node.js ≥ 18: `node --version` |
| EDR connection fails | Check API key permissions and network access |
| No alerts fetched | Verify lookback period and that alerts exist in your EDR |
| CORS error | Always access the UI via `sentinel_soc.html` with proxy running |

---

## 📦 Dependencies

```json
{
  "express":    "^4.18.2",
  "cors":       "^2.8.5",
  "node-fetch": "^3.3.2"
}
```

---

## 📝 License

MIT License — free to use, modify, and distribute.

---

## 🤝 Contributing

Pull requests welcome. Please open an issue first to discuss major changes.

---

*Built for SOC analysts who need faster visibility, not more noise.*
