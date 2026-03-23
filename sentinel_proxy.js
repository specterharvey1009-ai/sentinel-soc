/**
 * SENTINEL SOC — Proxy Server v3
 * ─────────────────────────────────────────────────────────────────
 * • CORS bypass for all EDR APIs
 * • AI chat with LIVE data: NVD hasKev API, CISA KEV feed, MITRE KB
 * • Built-in alert analysis engine (no external AI key required)
 *
 * Usage:
 *   npm install express node-fetch cors
 *   node sentinel_proxy.js
 *
 * Optional — Claude-powered AI:
 *   ANTHROPIC_API_KEY=sk-ant-... node sentinel_proxy.js
 */

'use strict';

const express = require('express');
const cors    = require('cors');
const fetch   = (...a) => import('node-fetch').then(({ default: f }) => f(...a));

const app  = express();
const PORT = 3847;

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '2mb' }));

// ── Simple TTL cache to avoid hammering public APIs ───────────────
const CACHE = new Map();
async function cached(key, ttlMs, fn) {
  const hit = CACHE.get(key);
  if (hit && (Date.now() - hit.ts) < ttlMs) return hit.val;
  const val = await fn();
  CACHE.set(key, { val, ts: Date.now() });
  return val;
}

// ════════════════════════════════════════════════════════════════
// HEALTH
// ════════════════════════════════════════════════════════════════
app.get('/health', (_, res) => res.json({
  status: 'ok',
  time:   new Date().toISOString(),
  mode:   process.env.ANTHROPIC_API_KEY ? 'claude-ai' : 'built-in-engine',
}));

// ════════════════════════════════════════════════════════════════
// CHAT — Multi-source real-time threat intelligence
// ════════════════════════════════════════════════════════════════
app.post('/chat', async (req, res) => {
  const { question, alertCtx = '', sessionCtx = '', history = [] } = req.body;
  if (!question) return res.status(400).json({ error: 'question is required' });

  try {
    if (process.env.ANTHROPIC_API_KEY) {
      const answer = await askClaude(question, alertCtx, sessionCtx, history);
      return res.json({ answer, source: 'claude' });
    }

    const intent   = classifyQuestion(question);
    const liveData = await gatherLiveIntel(question, intent);
    const answer   = buildAnswer(question, intent, liveData, alertCtx);

    res.json({ answer, source: 'built-in', sources_used: liveData.sources });
  } catch (err) {
    const answer = buildAnswer(question, classifyQuestion(question), { sources: [] }, alertCtx);
    res.json({ answer, source: 'fallback' });
  }
});

// ── Claude API ────────────────────────────────────────────────────
async function askClaude(question, alertCtx, sessionCtx, history) {
  const system = [
    'You are SENTINEL, a senior SOC analyst AI. Give precise, technical, actionable cybersecurity guidance.',
    alertCtx   ? `\nACTIVE ALERT: ${alertCtx}`   : '',
    sessionCtx ? `\nSESSION: ${sessionCtx}` : '',
    '\nRules: Never perform automated remediation — advise only.',
    'Use HTML: <strong>, <code>, <ul><li>, <div class="cmd">shell command</div>',
    'For MITRE techniques: <span class="mitre-pill">TXXXX</span>',
  ].join('');

  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method:  'POST',
    headers: {
      'Content-Type':      'application/json',
      'anthropic-version': '2023-06-01',
      'x-api-key':         process.env.ANTHROPIC_API_KEY,
    },
    body: JSON.stringify({
      model:      'claude-sonnet-4-20250514',
      max_tokens: 1200,
      system,
      messages: [...history.slice(-8), { role: 'user', content: question }],
    }),
  });

  if (!r.ok) {
    const e = await r.json().catch(() => ({}));
    throw new Error(e.error?.message || `Claude API ${r.status}`);
  }
  const d = await r.json();
  return d.content.map(b => b.text || '').join('');
}

// ── Live data gathering ───────────────────────────────────────────
async function gatherLiveIntel(question, intent) {
  const out = { sources: [] };

  const [mRes, nRes, cRes] = await Promise.allSettled([
    intent.needsMitre ? searchMitre(question)   : Promise.resolve(null),
    intent.needsCve   ? searchNvdLive(question) : Promise.resolve(null),
    intent.needsCisa  ? fetchKevLive(question)  : Promise.resolve(null),
  ]);

  if (mRes.status === 'fulfilled' && mRes.value?.length) { out.mitre = mRes.value; out.sources.push('MITRE ATT&CK'); }
  if (nRes.status === 'fulfilled' && nRes.value?.length) { out.cve   = nRes.value; out.sources.push('NIST NVD (live)'); }
  if (cRes.status === 'fulfilled' && cRes.value?.length) { out.kev   = cRes.value; out.sources.push('CISA KEV (live)'); }

  return out;
}

// ── LIVE NVD API — uses hasKev endpoint for security relevance ────
async function searchNvdLive(question) {
  const cveMatch = question.match(/CVE-\d{4}-\d+/i);

  if (cveMatch) {
    const id = cveMatch[0].toUpperCase();
    return cached('nvd:' + id, 3_600_000, async () => {
      const r = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`,
        { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(8000) }
      );
      if (!r.ok) return null;
      return parseNvd(await r.json());
    });
  }

  const kw = question.replace(/[^\w\s]/g, ' ').split(/\s+/).filter(w => w.length > 4).slice(0, 3).join(' ');
  if (!kw) return null;

  return cached('nvd:kw:' + kw, 1_800_000, async () => {
    // Try hasKev filter first — these are actively exploited, most relevant
    let r = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(kw)}&hasKev&resultsPerPage=4`,
      { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(8000) }
    );
    // Fall back to general search if no KEV results
    if (!r.ok || (await r.clone().json()).totalResults === 0) {
      r = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(kw)}&resultsPerPage=4`,
        { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(8000) }
      );
    }
    if (!r.ok) return null;
    return parseNvd(await r.json());
  });
}

function parseNvd(data) {
  return (data.vulnerabilities || []).slice(0, 5).map(v => {
    const cve  = v.cve;
    const m31  = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
    const m30  = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
    const m2   = cve.metrics?.cvssMetricV2?.[0]?.cvssData;
    const cvss = m31 || m30 || null;
    const score = cvss?.baseScore ?? m2?.baseScore ?? 'N/A';
    const sev   = cvss?.baseSeverity ?? (score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW');
    return {
      id:          cve.id,
      description: (cve.descriptions?.find(d => d.lang === 'en')?.value || '').slice(0, 250) + '…',
      score,
      severity:    sev,
      published:   (cve.published || '').split('T')[0],
      modified:    (cve.lastModified || '').split('T')[0],
      hasKev:      !!cve.cisaExploitAdd,
      kevDeadline: cve.cisaActionDue || null,
      url:         `https://nvd.nist.gov/vuln/detail/${cve.id}`,
    };
  }).filter(Boolean);
}

// ── LIVE CISA KEV catalog ─────────────────────────────────────────
async function fetchKevLive(question) {
  const catalog = await cached('cisa:kev', 3_600_000, async () => {
    const r = await fetch(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      { signal: AbortSignal.timeout(8000) }
    );
    if (!r.ok) return null;
    return r.json();
  });

  if (!catalog?.vulnerabilities) return null;

  const ql    = question.toLowerCase();
  const words = ql.split(/\s+/).filter(w => w.length > 3);

  return catalog.vulnerabilities
    .filter(v => {
      const hay = [v.cveID, v.vendorProject, v.product, v.vulnerabilityName, v.shortDescription].join(' ').toLowerCase();
      return words.some(w => hay.includes(w));
    })
    .slice(0, 4)
    .map(v => ({
      id:          v.cveID,
      product:     `${v.vendorProject} — ${v.product}`,
      name:        v.vulnerabilityName,
      description: (v.shortDescription || '').slice(0, 200) + '…',
      dateAdded:   v.dateAdded,
      dueDate:     v.dueDate,
      ransomware:  v.knownRansomwareCampaignUse === 'Known',
      url:         `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
    }));
}

// ── MITRE ATT&CK knowledge base ───────────────────────────────────
const TECHNIQUE_DB = {
  'T1003':    { name:'OS Credential Dumping',                        tactic:'Credential Access',   detail:'Dump credentials from LSASS, SAM, NTDS, DCSync. Tools: Mimikatz, ProcDump, comsvcs.dll. Detect: Event 4656/4663 on lsass.exe, Sysmon 10.' },
  'T1003.001':{ name:'LSASS Memory',                                 tactic:'Credential Access',   detail:'Read LSASS process memory. Tools: Mimikatz sekurlsa::, ProcDump -ma, Task Manager. Detect: Sysmon Event 10 on lsass.exe.' },
  'T1003.006':{ name:'DCSync',                                       tactic:'Credential Access',   detail:'Simulate DC replication to extract all hashes. Tools: Mimikatz lsadump::dcsync. Requires Replication rights. Detect: Event 4662.' },
  'T1021.002':{ name:'SMB/Windows Admin Shares',                     tactic:'Lateral Movement',    detail:'Move laterally via SMB admin shares. Tools: PsExec, Cobalt Strike, net use. Detect: Event 4624 Type 3, 4648.' },
  'T1021.001':{ name:'Remote Desktop Protocol',                      tactic:'Lateral Movement',    detail:'Use RDP for interactive sessions. Detect: Event 4624 Type 10, 4778.' },
  'T1059.001':{ name:'PowerShell',                                   tactic:'Execution',           detail:'Abuse PowerShell. Detect: Event 4104 (script block), 4103 (module). Enable logging via GPO.' },
  'T1059.003':{ name:'Windows Command Shell',                        tactic:'Execution',           detail:'Use cmd.exe. Detect: Event 4688 with command line logging.' },
  'T1027':    { name:'Obfuscated Files or Information',              tactic:'Defense Evasion',     detail:'Base64, XOR, packers, AMSI bypass. Detect: High entropy strings, AMSI telemetry.' },
  'T1053.005':{ name:'Scheduled Task',                               tactic:'Persistence',         detail:'Create tasks for persistence. Detect: Event 4698 (created), 4702 (modified).' },
  'T1547.001':{ name:'Registry Run Keys',                            tactic:'Persistence',         detail:'Write to Run keys. Detect: Sysmon Event 13 on HKCU/HKLM Run keys.' },
  'T1562.001':{ name:'Disable or Modify Tools',                      tactic:'Defense Evasion',     detail:'Disable AV/EDR. Detect: Defender tamper protection alerts, registry monitoring.' },
  'T1071.004':{ name:'DNS C2',                                       tactic:'Command and Control', detail:'DNS tunneling for C2. Tools: dnscat2, iodine. Detect: High query volume, >200 char subdomains, high entropy.' },
  'T1071.001':{ name:'Web Protocols',                                tactic:'Command and Control', detail:'HTTP/HTTPS C2. Tools: Cobalt Strike, Sliver. Detect: Beaconing, unusual user-agents, JA3 hashes.' },
  'T1558.003':{ name:'Kerberoasting',                                tactic:'Credential Access',   detail:'Request TGS for SPNs, crack offline. Tools: Rubeus, GetUserSPNs.py. Detect: Event 4769 with RC4 (0x17) spike.' },
  'T1558.001':{ name:'Golden Ticket',                                tactic:'Credential Access',   detail:'Forge TGTs using KRBTGT hash. Detect: Event 4769 for non-existent accounts.' },
  'T1490':    { name:'Inhibit System Recovery',                      tactic:'Impact',              detail:'Delete shadow copies. Commands: vssadmin delete shadows, wmic shadowcopy delete. Detect: Event 4688 on vssadmin.' },
  'T1486':    { name:'Data Encrypted for Impact',                    tactic:'Impact',              detail:'Ransomware encryption. Groups: LockBit 3.0, BlackCat, Clop, Black Basta, Akira.' },
  'T1105':    { name:'Ingress Tool Transfer',                        tactic:'Command and Control', detail:'Download tools via LOLBins: certutil, bitsadmin, mshta. Detect: Event 4688 for LOLBins with URLs.' },
  'T1550.002':{ name:'Pass the Hash',                                tactic:'Lateral Movement',    detail:'Auth with NTLM hash. Tools: Mimikatz pth, Impacket. Detect: Event 4624 Type 9 from workstations.' },
  'T1078':    { name:'Valid Accounts',                               tactic:'Defense Evasion',     detail:'Use legitimate credentials. Detect: Anomalous logon times/locations via UEBA.' },
  'T1136.001':{ name:'Create Local Account',                         tactic:'Persistence',         detail:'Create backdoor admin account. Detect: Event 4720, 4732.' },
  'T1112':    { name:'Modify Registry',                              tactic:'Defense Evasion',     detail:'Registry modifications for persistence or evasion. Detect: Sysmon Event 13.' },
  'T1566.001':{ name:'Spearphishing Attachment',                     tactic:'Initial Access',      detail:'Malicious attachments: macros, ISO, LNK. Detect: Office spawning child processes.' },
  'T1047':    { name:'Windows Management Instrumentation',           tactic:'Execution',           detail:'WMI execution. Detect: Sysmon 20/21, Event 4688 for wmic with remote node.' },
  'T1041':    { name:'Exfiltration Over C2 Channel',                 tactic:'Exfiltration',        detail:'Exfil over C2. Detect: Large outbound transfers, DLP alerts.' },
  'T1082':    { name:'System Information Discovery',                 tactic:'Discovery',           detail:'systeminfo, ver, hostname. Often precedes exploitation.' },
  'T1046':    { name:'Network Service Discovery',                    tactic:'Discovery',           detail:'Port scanning. Tools: nmap, netstat. Detect: Internal scan signatures.' },
};

function searchMitre(question) {
  const ql      = question.toLowerCase();
  const idMatch = question.match(/T(\d{4})(?:\.(\d{3}))?/i);
  const matches = new Map();

  if (idMatch) {
    const id = idMatch[0].toUpperCase();
    if (TECHNIQUE_DB[id]) matches.set(id, { id, ...TECHNIQUE_DB[id] });
    const parent = id.split('.')[0];
    if (TECHNIQUE_DB[parent] && parent !== id) matches.set(parent, { id: parent, ...TECHNIQUE_DB[parent] });
  }

  const words = ql.split(/\s+/).filter(w => w.length > 4);
  for (const [id, tech] of Object.entries(TECHNIQUE_DB)) {
    if (matches.has(id)) continue;
    const hay = `${tech.name} ${tech.tactic} ${tech.detail}`.toLowerCase();
    if (words.some(w => hay.includes(w))) matches.set(id, { id, ...tech });
    if (matches.size >= 5) break;
  }

  return Promise.resolve([...matches.values()].slice(0, 4));
}

// ── Question classification ───────────────────────────────────────
function classifyQuestion(q) {
  const ql = q.toLowerCase();
  return {
    needsMitre: /mitre|att&?ck|technique|tactic|t\d{4}|ttp|lateral|persistence|evasion|exfil|c2|command.?control|credential|kerbero|psexec|mimikatz|cobalt|beacon|lsass|scheduled.task|pass.the/.test(ql),
    needsCve:   /cve|vuln|exploit|patch|cvss|zero.?day|rce|lpe|privilege.?esc|log4|proxyshell|eternalblue|cve-\d/.test(ql),
    needsCisa:  /cisa|kev|known.exploit|advisory|ransomware.group|actively.exploit|patch.deadline/.test(ql),
    topic:      detectTopic(ql),
  };
}

function detectTopic(q) {
  if (/ransomware|encrypt|decrypt|ransom|lockbit|blackcat|clop/.test(q))          return 'ransomware';
  if (/phishing|spear|email|attachment|macro|bec|html.smug/.test(q))             return 'phishing';
  if (/mimikatz|lsass|credential|dump|password|hash|dcsync|ntds/.test(q))        return 'credential_dump';
  if (/lateral|psexec|wmi|smb|rdp|pass.the|pivot/.test(q))                       return 'lateral_movement';
  if (/persist|scheduled.task|registry|autorun|startup|run.key/.test(q))         return 'persistence';
  if (/defender|antivirus|edr|amsi|bypass|tamper|disable.av/.test(q))            return 'defense_evasion';
  if (/dns.tunnel|beacon|c2|command.control|cobalt|sliver|brute.ratel/.test(q))  return 'c2';
  if (/log|siem|splunk|elastic|kql|sentinel|query|hunt|detect/.test(q))          return 'threat_hunting';
  if (/isolat|contain|incident|respond|ir.plan|playbook|eradicate/.test(q))      return 'incident_response';
  if (/mitre|t\d{4}|ttp|technique|tactic/.test(q))                               return 'mitre';
  if (/cve|vuln|patch|exploit|cvss/.test(q))                                     return 'vulnerability';
  if (/apt|nation|group|actor|lazarus|cozy|fancy|scattered|spider/.test(q))      return 'threat_actor';
  if (/ioc|indicator|hash|ip.block|domain.block|feed|threat.intel/.test(q))      return 'ioc';
  if (/kerbero|golden.ticket|silver.ticket|as-rep|tgs|tgt/.test(q))              return 'kerberos';
  if (/cloud|aws|azure|gcp|s3|iam|okta|saml|oauth/.test(q))                      return 'cloud';
  return 'general';
}

// ── Answer builder ────────────────────────────────────────────────
function buildAnswer(question, intent, liveData, alertCtx) {
  const { mitre = [], cve = [], kev = [], sources = [] } = liveData;
  let out = '';

  if (alertCtx) {
    out += `<div style="background:rgba(0,229,255,.06);border-left:3px solid var(--cyan);padding:7px 12px;margin-bottom:12px;font-size:11px;font-family:var(--mono);border-radius:0 4px 4px 0"><strong style="color:var(--cyan)">🔗 Alert context:</strong> ${alertCtx}</div>`;
  }

  // Core answer from knowledge base
  const kbFn = KB_ANSWERS[intent.topic] || KB_ANSWERS.general;
  out += kbFn(question);

  // Live MITRE data
  if (mitre.length) {
    out += `<h3 style="color:var(--cyan);font-size:11px;font-family:var(--mono);letter-spacing:2px;text-transform:uppercase;margin:14px 0 8px;padding-bottom:5px;border-bottom:1px solid rgba(0,229,255,.15)">⚔ MITRE ATT&CK</h3>`;
    mitre.forEach(t => {
      out += `<div style="background:rgba(213,0,249,.07);border:1px solid rgba(213,0,249,.2);border-radius:5px;padding:8px 12px;margin-bottom:7px">
        <span class="mitre-pill">${t.id}</span> <strong>${t.name}</strong> <span style="color:var(--text2);font-size:10px;font-family:var(--mono)">— ${t.tactic}</span><br>
        <span style="font-size:11px;color:var(--text1);line-height:1.6">${t.detail}</span><br>
        <a href="https://attack.mitre.org/techniques/${t.id.replace('.','/')}/" style="font-size:10px;color:var(--cyan)" target="_blank">→ MITRE ATT&CK: ${t.id}</a>
      </div>`;
    });
  }

  // Live CVE data
  if (cve.length) {
    out += `<h3 style="color:var(--cyan);font-size:11px;font-family:var(--mono);letter-spacing:2px;text-transform:uppercase;margin:14px 0 8px;padding-bottom:5px;border-bottom:1px solid rgba(0,229,255,.15)">🔓 CVE DATA — NIST NVD (LIVE)</h3>`;
    cve.forEach(v => {
      const sc  = parseFloat(v.score);
      const col = sc >= 9 ? 'var(--red)' : sc >= 7 ? 'var(--orange2)' : sc >= 4 ? 'var(--yellow)' : 'var(--green)';
      out += `<div style="background:var(--bg3);border:1px solid var(--border2);border-radius:5px;padding:9px 12px;margin-bottom:7px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:5px">
          <strong style="color:var(--cyan);font-family:var(--mono)">${v.id}</strong>
          <span style="font-family:var(--mono);font-size:10px;color:${col};font-weight:700">CVSS ${v.score} — ${v.severity}</span>
        </div>
        ${v.hasKev ? `<span style="background:rgba(255,23,68,.2);color:var(--red);font-size:9px;padding:1px 7px;border-radius:3px;font-family:var(--mono);font-weight:700;display:inline-block;margin-bottom:5px">⚠ CISA KEV — ACTIVELY EXPLOITED${v.kevDeadline ? ' · Patch by ' + v.kevDeadline : ''}</span><br>` : ''}
        <span style="font-size:11px;color:var(--text1);line-height:1.6">${v.description}</span><br>
        <span style="font-family:var(--mono);font-size:10px;color:var(--text3)">Published: ${v.published} · Modified: ${v.modified}</span>
        <a href="${v.url}" style="font-size:10px;color:var(--cyan);margin-left:10px" target="_blank">→ NVD Details</a>
      </div>`;
    });
  }

  // Live CISA KEV data
  if (kev.length) {
    out += `<h3 style="color:var(--red);font-size:11px;font-family:var(--mono);letter-spacing:2px;text-transform:uppercase;margin:14px 0 8px;padding-bottom:5px;border-bottom:1px solid rgba(255,23,68,.2)">🚨 CISA KNOWN EXPLOITED VULNERABILITIES (LIVE)</h3>`;
    kev.forEach(v => {
      out += `<div style="background:rgba(255,23,68,.06);border:1px solid rgba(255,23,68,.2);border-radius:5px;padding:9px 12px;margin-bottom:7px">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <strong style="color:var(--red);font-family:var(--mono)">${v.id}</strong>
          ${v.ransomware ? '<span style="background:rgba(255,23,68,.25);color:var(--red);font-size:9px;padding:1px 7px;border-radius:3px;font-family:var(--mono);font-weight:700">RANSOMWARE</span>' : ''}
        </div>
        <div style="font-size:11px;color:var(--text2);font-family:var(--mono);margin:3px 0">${v.product}</div>
        <div style="font-size:11px;color:var(--text1);line-height:1.6;margin-bottom:4px">${v.description}</div>
        <div style="font-family:var(--mono);font-size:10px;color:var(--text3)">Added: ${v.dateAdded} · <span style="color:var(--orange2)">CISA Patch Deadline: ${v.dueDate}</span></div>
        <a href="${v.url}" style="font-size:10px;color:var(--cyan)" target="_blank">→ NVD</a>
        <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" style="font-size:10px;color:var(--red);margin-left:10px" target="_blank">→ CISA KEV Catalog</a>
      </div>`;
    });
  }

  // Sources footer
  if (sources.length) {
    out += `<div style="margin-top:10px;padding-top:8px;border-top:1px solid var(--border);font-family:var(--mono);font-size:9px;color:var(--text3)">📡 Sources: ${sources.join(' · ')} · ${new Date().toUTCString()}</div>`;
  }

  return out;
}

// ── Knowledge base answers ────────────────────────────────────────
const KB_ANSWERS = {
  credential_dump: () => `<strong>Credential Dumping</strong> — critical post-exploitation technique.<br><br>
<strong>Methods:</strong>
<ul>
  <li><strong>LSASS:</strong> Mimikatz <code>sekurlsa::logonpasswords</code>, ProcDump <code>-ma lsass.exe</code>, comsvcs.dll MiniDump</li>
  <li><strong>SAM/SYSTEM:</strong> <code>reg save HKLM\\SAM sam.bak</code> + <code>reg save HKLM\\SYSTEM sys.bak</code></li>
  <li><strong>DCSync:</strong> <code>lsadump::dcsync /domain:corp.local /all</code> — replicates all hashes from DC</li>
  <li><strong>NTDS.dit:</strong> Direct extraction from Domain Controller</li>
</ul>
<strong>Detection:</strong>
<div class="cmd">Get-WinEvent -FilterHashtable @{LogName='Security';Id=4656} | Where {$_.Message -like '*lsass*'}</div>
<strong>Response:</strong>
<ul>
  <li>Isolate endpoint immediately</li>
  <li>Force password reset for <strong>ALL</strong> accounts that logged into this host</li>
  <li>Enable Credential Guard via Group Policy</li>
  <li>Add affected accounts to Protected Users security group</li>
</ul>`,

  lateral_movement: () => `<strong>Lateral Movement</strong> — spreading from foothold to high-value targets.<br><br>
<strong>Top techniques:</strong>
<ul>
  <li><span class="mitre-pill">T1550.002</span> <strong>Pass-the-Hash:</strong> NTLM hash reuse — <code>sekurlsa::pth /user:admin /ntlm:HASH</code></li>
  <li><span class="mitre-pill">T1021.002</span> <strong>PsExec:</strong> <code>psexec \\\\TARGET -s cmd</code> via SMB admin shares</li>
  <li><span class="mitre-pill">T1047</span> <strong>WMI:</strong> <code>wmic /node:TARGET process call create "cmd /c payload"</code></li>
  <li><span class="mitre-pill">T1021.001</span> <strong>RDP:</strong> Stolen credentials + RDP (Event 4624 Type 10)</li>
</ul>
<strong>Detection:</strong>
<div class="cmd">Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} | Where {$_.Message -match 'Logon Type:\\s+3'}</div>
<div class="cmd">Get-WinEvent -FilterHashtable @{LogName='System';Id=7045} | Select TimeCreated,Message</div>
<strong>Containment:</strong>
<ul>
  <li>Isolate source AND destination hosts</li>
  <li>Block port 445 between workstation segments</li>
  <li>Deploy LAPS — prevents hash reuse across workstations</li>
</ul>`,

  ransomware: () => `<strong>🚨 Ransomware Response — every minute counts.</strong><br><br>
<strong>First 15 minutes:</strong>
<ul>
  <li>🔴 <strong>Isolate ALL affected hosts from network immediately</strong></li>
  <li>Do NOT reboot — memory forensics will be lost</li>
  <li>Preserve disk images BEFORE any recovery</li>
  <li>Contact IR retainer + cyber insurance NOW</li>
</ul>
<strong>Hunt RIGHT NOW on other hosts:</strong>
<ul>
  <li>VSS deletion: <code>vssadmin delete shadows /all</code>, <code>wmic shadowcopy delete</code></li>
  <li>Defender disabling, backup tampering</li>
  <li>Net discovery: <code>net view /all</code>, <code>nltest /dclist</code>, <code>AdFind.exe</code></li>
  <li>Mass SMB connections to file shares from single host</li>
</ul>
<strong>Active groups (2025):</strong> LockBit 3.0, BlackCat/ALPHV, Clop, Black Basta, Akira, Play, Rhysida<br><br>
<strong>Recovery sequence:</strong> Contain → Eradicate → Restore from clean backup → Patch → Monitor`,

  phishing: () => `<strong>Phishing — #1 initial access vector.</strong><br><br>
<strong>Modern delivery (2024-2025):</strong>
<ul>
  <li>ISO/IMG/ZIP + LNK files (bypasses Mark-of-the-Web)</li>
  <li>HTML smuggling — payload decoded client-side</li>
  <li>QR codes in PDF attachments (bypasses email scanning)</li>
  <li>AiTM phishing (Evilginx2) — steals session tokens, bypasses MFA</li>
</ul>
<strong>Detect macro/script execution:</strong>
<div class="cmd">Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} | Where {$_.Message -match 'winword|excel'} | Where {$_.Message -match 'powershell|cmd|wscript|mshta'}</div>
<strong>Response:</strong>
<ul>
  <li>Block sender domain at email gateway</li>
  <li>Search all mailboxes for same sender/attachment hash</li>
  <li>Identify and isolate all endpoints that opened the attachment</li>
</ul>`,

  persistence: () => `<strong>Persistence Mechanisms</strong><br><br>
<strong>Check these locations:</strong>
<ul>
  <li><strong>Registry Run Keys:</strong> <code>HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</code></li>
  <li><strong>Scheduled Tasks:</strong> <code>schtasks /query /fo LIST /v</code> — Event ID 4698</li>
  <li><strong>Services:</strong> Event ID 7045 — new service installed</li>
  <li><strong>Startup Folder:</strong> <code>%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup</code></li>
  <li><strong>WMI Subscriptions:</strong> <code>Get-WMIObject -Namespace root\\subscription -Class __EventFilter</code></li>
</ul>
<strong>Full audit with Autoruns:</strong>
<div class="cmd">autorunsc.exe -a * -c -h -s -u -vt > autoruns.csv</div>`,

  defense_evasion: () => `<strong>Defense Evasion</strong><br><br>
<strong>Current techniques:</strong>
<ul>
  <li><strong>AMSI Bypass:</strong> Patch <code>amsi.dll</code> in memory — disables PowerShell/VBA scanning</li>
  <li><strong>ETW Patching:</strong> Blind event tracing — hides activity from EDR</li>
  <li><strong>LOLBins:</strong> certutil, mshta, regsvr32, rundll32 for payload delivery</li>
  <li><strong>BYOVD:</strong> Bring Your Own Vulnerable Driver — kills EDR at kernel level</li>
</ul>
<strong>Detect LOLBin abuse:</strong>
<div class="cmd">Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} | Where {$_.Message -match 'certutil|mshta|regsvr32|rundll32'}</div>
<strong>Re-enable Defender:</strong>
<div class="cmd">Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false</div>`,

  c2: () => `<strong>Command & Control Detection</strong><br><br>
<strong>Common frameworks (2025):</strong>
<ul>
  <li><strong>Cobalt Strike:</strong> HTTP/HTTPS/DNS/SMB beacons. Hunt: named pipe <code>\\\\pipe\\\\MSSE-*</code></li>
  <li><strong>Sliver:</strong> mTLS/WireGuard/HTTP3 — increasingly common post-CS</li>
  <li><strong>Brute Ratel:</strong> EDR-evasion focused, no CS markers, used by APT groups</li>
  <li><strong>DNS tunneling:</strong> dnscat2, iodine — high query rate, long base64 subdomains</li>
</ul>
<strong>Hunt for beacons:</strong>
<div class="cmd">Get-NetTCPConnection -State Established | Where RemotePort -in @(443,80,8080,8443,4444) | Select LocalAddress,RemoteAddress,@{n='Process';e={(Get-Process -Id $_.OwningProcess).Name}}</div>
<strong>Disruption:</strong>
<ul>
  <li>Null-route C2 domain/IP at DNS + firewall</li>
  <li>Capture memory image BEFORE isolating host for IOC extraction</li>
</ul>`,

  threat_hunting: () => `<strong>Threat Hunting</strong> — proactive detection.<br><br>
<strong>High-value hunts:</strong>
<ul>
  <li><strong>Beacon detection:</strong> Processes with periodic outbound connections every 30-60s</li>
  <li><strong>Kerberoasting:</strong> Event 4769 with RC4 encryption (0x17) spike</li>
  <li><strong>Pass-the-Hash:</strong> Event 4624 Type 9 from workstations</li>
  <li><strong>LOLBin + network:</strong> certutil/mshta with outbound connections</li>
  <li><strong>LSASS access:</strong> Sysmon Event 10 on lsass.exe from non-system processes</li>
</ul>
<strong>KQL (Microsoft Sentinel / Defender):</strong>
<div class="cmd">DeviceProcessEvents | where FileName in~ ("certutil.exe","mshta.exe","regsvr32.exe") | where ProcessCommandLine matches regex @"http|//" | project Timestamp, DeviceName, FileName, ProcessCommandLine</div>
<strong>Splunk:</strong>
<div class="cmd">index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 | stats count by src_ip,Account_Name | where count > 5</div>`,

  incident_response: () => `<strong>Incident Response — NIST SP 800-61</strong><br><br>
<strong>IR Phases:</strong>
<ul>
  <li><strong>1. Preparation:</strong> IR plan, runbooks, tooling, legal retainer</li>
  <li><strong>2. Detection & Analysis:</strong> Confirm scope, triage, severity classification</li>
  <li><strong>3. Containment:</strong> Isolate affected systems, block attack vector</li>
  <li><strong>4. Eradication:</strong> Remove malware, close entry point, patch</li>
  <li><strong>5. Recovery:</strong> Restore from clean backup, monitor</li>
  <li><strong>6. Lessons Learned:</strong> Root cause, gaps, report, update detections</li>
</ul>
<strong>First 30 minutes checklist:</strong>
<ul>
  <li>☐ Confirm it's real — rule out false positive</li>
  <li>☐ Scope affected systems, users, data</li>
  <li>☐ Activate IR team, notify management + legal</li>
  <li>☐ Preserve evidence: logs, memory dumps, disk images</li>
  <li>☐ Contain — isolate WITHOUT rebooting</li>
  <li>☐ Begin attack timeline reconstruction</li>
</ul>`,

  kerberos: () => `<strong>Kerberos Attacks</strong><br><br>
<ul>
  <li><span class="mitre-pill">T1558.003</span> <strong>Kerberoasting:</strong> Request TGS for SPNs, crack RC4 hash offline. Tool: Rubeus, GetUserSPNs.py. Detect: Event 4769 RC4 (0x17) spike.</li>
  <li><span class="mitre-pill">T1558.004</span> <strong>AS-REP Roasting:</strong> No pre-auth required accounts. Detect: Event 4768 no pre-auth flag.</li>
  <li><span class="mitre-pill">T1558.001</span> <strong>Golden Ticket:</strong> Forge TGT using KRBTGT hash. Detect: Event 4769 for non-existent accounts.</li>
  <li><span class="mitre-pill">T1550.003</span> <strong>Pass-the-Ticket:</strong> Inject stolen Kerberos ticket.</li>
</ul>
<strong>Detect Kerberoasting:</strong>
<div class="cmd">Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} | Where {$_.Message -like '*0x17*'} | Group-Object {$_.Properties[1].Value} | Where Count -gt 5</div>
<strong>Mitigation:</strong> AES-only encryption for service accounts, gMSA, 25+ char service account passwords.`,

  cloud: () => `<strong>Cloud Security Threats</strong><br><br>
<strong>Common attack paths:</strong>
<ul>
  <li><strong>Exposed credentials:</strong> API keys in GitHub, env vars, S3 buckets</li>
  <li><strong>IAM privilege escalation:</strong> Overly permissive roles, PassRole abuse</li>
  <li><strong>SSRF → metadata service:</strong> IMDSv1 credential theft</li>
  <li><strong>OAuth/SAML abuse:</strong> Consent phishing, token theft, SAML forgery</li>
  <li><strong>Resource hijacking:</strong> Cryptomining via compromised cloud credentials</li>
</ul>
<strong>Azure Sentinel KQL — detect IAM changes:</strong>
<div class="cmd">AzureActivity | where OperationNameValue contains "roleAssignments/write" | where ActivityStatusValue == "Success" | project TimeGenerated,Caller,ResourceGroup,OperationNameValue</div>`,

  threat_actor: () => `<strong>Threat Actor Intelligence (2025)</strong><br><br>
<strong>Active APT groups:</strong>
<ul>
  <li><strong>Lazarus Group (DPRK):</strong> Crypto theft, supply chain, custom loaders, macOS malware</li>
  <li><strong>APT29/Cozy Bear (Russia/SVR):</strong> Cloud-focused espionage, OAuth abuse, MFA bypass</li>
  <li><strong>APT41 (China):</strong> Dual espionage + cybercrime, healthcare, telecom</li>
  <li><strong>Scattered Spider:</strong> Social engineering, SIM swapping, MFA fatigue — MGM breach</li>
  <li><strong>Volt Typhoon (China):</strong> Critical infrastructure, LOLBins only, living-off-the-land</li>
</ul>
<strong>Active ransomware groups:</strong> LockBit 3.0, BlackCat/ALPHV, Clop, Black Basta, Akira, Play, Rhysida<br><br>
<strong>Intelligence feeds:</strong>
<ul>
  <li><a href="https://attack.mitre.org/groups/" style="color:var(--cyan)" target="_blank">MITRE ATT&CK Groups</a></li>
  <li><a href="https://www.cisa.gov/news-events/cybersecurity-advisories" style="color:var(--cyan)" target="_blank">CISA Advisories</a></li>
  <li><a href="https://otx.alienvault.com" style="color:var(--cyan)" target="_blank">AlienVault OTX</a></li>
</ul>`,

  ioc: () => `<strong>IOC Management</strong><br><br>
<strong>Block by IOC type:</strong>
<ul>
  <li><strong>File hashes:</strong> EDR custom block policy, AV signatures, YARA rules</li>
  <li><strong>IPs:</strong> Firewall outbound block, proxy deny list</li>
  <li><strong>Domains:</strong> DNS sinkhole, proxy block, firewall FQDN rule</li>
  <li><strong>Email:</strong> Mail gateway sender/domain block</li>
</ul>
<strong>Free lookup sources:</strong>
<ul>
  <li><a href="https://www.virustotal.com" style="color:var(--cyan)" target="_blank">VirusTotal</a> — hashes, IPs, domains, URLs</li>
  <li><a href="https://otx.alienvault.com" style="color:var(--cyan)" target="_blank">AlienVault OTX</a> — threat pulses</li>
  <li><a href="https://www.abuseipdb.com" style="color:var(--cyan)" target="_blank">AbuseIPDB</a> — malicious IPs</li>
  <li><a href="https://urlhaus.abuse.ch" style="color:var(--cyan)" target="_blank">URLhaus</a> — malware URLs</li>
  <li><a href="https://bazaar.abuse.ch" style="color:var(--cyan)" target="_blank">MalwareBazaar</a> — file hashes</li>
</ul>`,

  vulnerability: () => `<strong>Vulnerability Prioritization</strong><br><br>
<strong>Patch in this order:</strong>
<ul>
  <li><strong>1. CISA KEV + CVSS ≥ 9:</strong> Patch within 24 hours</li>
  <li><strong>2. CISA KEV:</strong> Patch within 24-48 hours per CISA deadline</li>
  <li><strong>3. CVSS ≥ 9 + public exploit:</strong> Patch within 48-72 hours</li>
  <li><strong>4. CVSS 7-8.9:</strong> Patch within 7-14 days</li>
  <li><strong>5. CVSS 4-6.9:</strong> 30-day cycle</li>
</ul>
<strong>Key resources:</strong>
<ul>
  <li><a href="https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev" style="color:var(--cyan)" target="_blank">NVD KEV API</a> — all actively exploited CVEs</li>
  <li><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" style="color:var(--cyan)" target="_blank">CISA KEV Catalog</a></li>
  <li><a href="https://nvd.nist.gov" style="color:var(--cyan)" target="_blank">NIST NVD</a></li>
</ul>`,

  mitre: () => `<strong>MITRE ATT&CK Framework</strong><br><br>
<strong>14 Tactics:</strong> Reconnaissance · Resource Development · Initial Access · Execution · Persistence · Privilege Escalation · Defense Evasion · Credential Access · Discovery · Lateral Movement · Collection · Command and Control · Exfiltration · Impact<br><br>
<strong>Most abused techniques (2025):</strong>
<ul>
  <li><span class="mitre-pill">T1059.001</span> PowerShell execution</li>
  <li><span class="mitre-pill">T1003.001</span> LSASS credential dumping</li>
  <li><span class="mitre-pill">T1486</span> Data encrypted for impact (ransomware)</li>
  <li><span class="mitre-pill">T1566.001</span> Spearphishing attachment</li>
  <li><span class="mitre-pill">T1078</span> Valid accounts</li>
  <li><span class="mitre-pill">T1071.001</span> HTTP/S C2</li>
</ul>
<strong>Resources:</strong>
<ul>
  <li><a href="https://attack.mitre.org" style="color:var(--cyan)" target="_blank">attack.mitre.org</a></li>
  <li><a href="https://mitre-attack.github.io/attack-navigator/" style="color:var(--cyan)" target="_blank">ATT&CK Navigator</a></li>
  <li><a href="https://car.mitre.org" style="color:var(--cyan)" target="_blank">MITRE CAR — detection analytics</a></li>
</ul>`,

  general: (q) => `I'm <strong>SENTINEL</strong>, your SOC assistant. I can help with:<br><br>
<ul>
  <li>🔍 <strong>Alert analysis</strong> — explain any EDR detection</li>
  <li>⚔ <strong>MITRE ATT&CK</strong> — techniques, detection, response</li>
  <li>🔓 <strong>CVE lookups</strong> — live NIST NVD data (try: <em>"CVE-2024-21413"</em>)</li>
  <li>🚨 <strong>CISA KEV</strong> — actively exploited vulns + patch deadlines</li>
  <li>🛡 <strong>Incident response</strong> — IR playbooks</li>
  <li>🔎 <strong>Threat hunting</strong> — PowerShell, Splunk, KQL queries</li>
  <li>👥 <strong>Threat actors</strong> — APT profiles, ransomware groups</li>
  <li>☁ <strong>Cloud security</strong> — AWS, Azure, GCP attack paths</li>
</ul>
Try: <em>"How do I detect Kerberoasting?"</em> · <em>"CVE-2024-21413"</em> · <em>"What is T1003.001?"</em> · <em>"How do I respond to ransomware?"</em>`,
};

// ════════════════════════════════════════════════════════════════
// ALERT ANALYSIS ENGINE
// ════════════════════════════════════════════════════════════════
app.post('/ai', async (req, res) => {
  const { messages, system, max_tokens = 1500 } = req.body;
  if (!messages?.length) return res.status(400).json({ error: 'messages required' });

  const prompt = messages.filter(m => m.role === 'user').pop()?.content || '';

  try {
    if (process.env.ANTHROPIC_API_KEY) {
      const r = await fetch('https://api.anthropic.com/v1/messages', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', 'anthropic-version': '2023-06-01', 'x-api-key': process.env.ANTHROPIC_API_KEY },
        body:    JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens, ...(system ? { system } : {}), messages }),
      });
      return res.status(r.status).json(await r.json());
    }

    res.json({ content: [{ type: 'text', text: analyzeAlertPrompt(prompt) }], stop_reason: 'end_turn' });
  } catch (err) {
    res.status(502).json({ error: { message: err.message } });
  }
});

function analyzeAlertPrompt(prompt) {
  const get  = (re) => (prompt.match(re)?.[1] || '').trim();
  const p    = prompt.toLowerCase();
  const title    = get(/Title:\s*(.+)/);
  const severity = get(/Severity:\s*(\w+)/);
  const endpoint = get(/Endpoint:\s*(.+)/);
  const user     = get(/User:\s*(.+)/);
  const process  = get(/Process:\s*(.+)/);
  const rawEvent = get(/Raw Event:\s*(.+)/);
  const topic    = detectTopic(p);
  const sevEmoji = { CRITICAL:'🔴', HIGH:'🟠', MEDIUM:'🟡', LOW:'🟢' }[severity.toUpperCase()] || '🟠';

  const words    = p.split(/\s+/).filter(w => w.length > 4);
  const techniques = [];
  for (const [id, tech] of Object.entries(TECHNIQUE_DB)) {
    const hay = `${tech.name} ${tech.detail}`.toLowerCase();
    if (words.some(w => hay.includes(w))) techniques.push({ id, ...tech });
    if (techniques.length >= 4) break;
  }

  const STEPS = {
    credential_dump:  { i:['Check LSASS access: <div class="cmd">Get-WinEvent -FilterHashtable @{LogName=\'Security\';Id=4656} | Where {$_.Message -like \'*lsass*\'}</div>','List all accounts logged into this host — all must have passwords reset','Hunt for credential files on disk: <div class="cmd">Get-ChildItem C:\\ -Recurse -Include *.dmp,*.dump -ErrorAction SilentlyContinue</div>'], c:['Isolate endpoint immediately via EDR','Force password reset on ALL accounts that touched this host','Enable Credential Guard via Group Policy (requires reboot)'] },
    lateral_movement: { i:['Map lateral connections: <div class="cmd">Get-WinEvent -FilterHashtable @{LogName=\'Security\';Id=4624} | Where {$_.Message -match \'Logon Type:\\s+3\'}</div>','Check for remotely installed services (Event 7045)','Review all systems this host communicated with in last 24h via EDR'], c:['Isolate BOTH source and destination hosts','Block SMB port 445 between workstation segments','Remove remote services: <div class="cmd">sc delete PSEXESVC</div>'] },
    ransomware:       { i:['Determine encryption scope — how many files affected?','Check VSS: <div class="cmd">vssadmin list shadows</div>','Identify patient zero — which host started encryption?'], c:['🔴 DISCONNECT ALL AFFECTED HOSTS FROM NETWORK NOW','Do NOT reboot — preserve forensic evidence','Activate IR retainer and cyber insurance immediately'] },
    persistence:      { i:['List scheduled tasks: <div class="cmd">schtasks /query /fo LIST /v | findstr "Task Name\\|Run As User"</div>','Check run keys: <div class="cmd">reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</div>','Check startup folder contents'], c:['Delete malicious task: <div class="cmd">schtasks /delete /tn "\\TASKNAME" /f</div>','Remove malicious run key','Block file hash in EDR custom policy'] },
    defense_evasion:  { i:['Check Defender status: <div class="cmd">Get-MpComputerStatus | Select RealTimeProtectionEnabled,AntivirusEnabled</div>','Review security registry keys: <div class="cmd">reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"</div>','Identify activity during the window AV was disabled'], c:['Re-enable Defender: <div class="cmd">Set-MpPreference -DisableRealtimeMonitoring $false</div>','Restore registry: <div class="cmd">reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0 /f</div>','Force full scan: <div class="cmd">Start-MpScan -ScanType FullScan</div>'] },
    c2:               { i:['Identify C2 process: <div class="cmd">Get-NetTCPConnection -State Established | Select LocalAddress,RemoteAddress,@{n=\'P\';e={(Get-Process -Id $_.OwningProcess).Name}}</div>','Capture and analyze DNS query logs for past 24h','Check for DNS tunneling: high query volume + long subdomain names'], c:['Block C2 domain/IP at firewall and DNS resolver','Capture memory image before isolation','Search for same C2 IOCs across ALL endpoints'] },
  };

  const tmpl = STEPS[topic] || STEPS.persistence;

  return `
<h3>🎯 What Happened</h3>
<p>${sevEmoji} <strong>${title || 'Security Alert'}</strong> detected on <code>${endpoint || 'Unknown'}</code> (user: <code>${user || 'Unknown'}</code>, process: <code>${process || 'Unknown'}</code>).${rawEvent ? ' ' + rawEvent : ''}</p>

<h3>⚔ MITRE ATT&CK Mapping</h3>
<p>${techniques.length ? techniques.map(t => `<span class="mitre-pill">${t.id}</span> <strong>${t.name}</strong> — ${t.tactic}`).join('<br>') : '<span class="mitre-pill">T1059</span> <strong>Command and Scripting Interpreter</strong> — Execution'}</p>

<h3>🔍 Investigation Steps</h3>
<ul>${tmpl.i.map((s, i) => `<li><strong>Step ${i+1}:</strong> ${s}</li>`).join('')}</ul>

<h3>🛡 Containment</h3>
<ul>${tmpl.c.map((s, i) => `<li><strong>${i+1}.</strong> ${s}</li>`).join('')}</ul>

<h3>🔒 IOC Blocking</h3>
<ul>
  <li>Add all IOCs to EDR custom block policy</li>
  <li>Add C2 IPs/domains to firewall deny list and DNS sinkhole</li>
  <li>Search for same IOCs across ALL endpoints in the environment</li>
</ul>`.trim();
}

// ════════════════════════════════════════════════════════════════
// EDR API SHORTCUTS
// ════════════════════════════════════════════════════════════════
app.post('/s1/test', async (req, res) => {
  const { token, baseUrl } = req.body;
  if (!token || !baseUrl) return res.status(400).json({ error: 'token and baseUrl required' });
  try {
    const r = await fetch(`${baseUrl}/web/api/v2.1/system/status`, { headers: { Authorization: `ApiToken ${token}`, Accept: 'application/json' } });
    res.json({ ok: r.ok, status: r.status, data: await r.json() });
  } catch(e) { res.status(502).json({ ok: false, error: e.message }); }
});

app.post('/s1/threats', async (req, res) => {
  const { token, baseUrl, since, limit = 100 } = req.body;
  if (!token || !baseUrl) return res.status(400).json({ error: 'token and baseUrl required' });
  try {
    const r = await fetch(`${baseUrl}/web/api/v2.1/threats?createdAt__gte=${since}&limit=${limit}&sortBy=createdAt&sortOrder=desc`, { headers: { Authorization: `ApiToken ${token}`, Accept: 'application/json' } });
    res.json({ ok: r.ok, status: r.status, data: await r.json() });
  } catch(e) { res.status(502).json({ ok: false, error: e.message }); }
});

app.post('/cs/auth', async (req, res) => {
  const { clientId, clientSecret, baseUrl = 'https://api.crowdstrike.com' } = req.body;
  try {
    const r = await fetch(`${baseUrl}/oauth2/token`, { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded',Accept:'application/json'}, body:`client_id=${encodeURIComponent(clientId)}&client_secret=${encodeURIComponent(clientSecret)}` });
    res.json({ ok: r.ok, status: r.status, data: await r.json() });
  } catch(e) { res.status(502).json({ ok: false, error: e.message }); }
});

app.post('/cs/detections', async (req, res) => {
  const { token, baseUrl = 'https://api.crowdstrike.com', since, limit = 100 } = req.body;
  try {
    const qr = await fetch(`${baseUrl}/detects/queries/detects/v1?filter=created_timestamp:>='${since}'&limit=${limit}&sort=created_timestamp.desc`, { headers:{ Authorization:`Bearer ${token}`, Accept:'application/json' } });
    const qd = await qr.json();
    const ids = (qd.resources || []).slice(0, 50);
    if (!ids.length) return res.json({ ok: true, data: { resources: [] } });
    const dr = await fetch(`${baseUrl}/detects/entities/summaries/GET/v1`, { method:'POST', headers:{ Authorization:`Bearer ${token}`, Accept:'application/json', 'Content-Type':'application/json' }, body: JSON.stringify({ ids }) });
    res.json({ ok: dr.ok, status: dr.status, data: await dr.json() });
  } catch(e) { res.status(502).json({ ok: false, error: e.message }); }
});

app.post('/mde/auth', async (req, res) => {
  const { tenantId, clientId, clientSecret } = req.body;
  try {
    const r = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:`client_id=${encodeURIComponent(clientId)}&client_secret=${encodeURIComponent(clientSecret)}&scope=https://api.securitycenter.microsoft.com/.default&grant_type=client_credentials` });
    res.json({ ok: r.ok, status: r.status, data: await r.json() });
  } catch(e) { res.status(502).json({ ok: false, error: e.message }); }
});

app.post('/mde/alerts', async (req, res) => {
  const { token, since, limit = 100 } = req.body;
  try {
    const r = await fetch(`https://api.securitycenter.microsoft.com/api/alerts?$filter=alertCreationTime ge ${since}&$orderby=alertCreationTime desc&$top=${limit}`, { headers:{ Authorization:`Bearer ${token}`, Accept:'application/json' } });
    res.json({ ok: r.ok, status: r.status, data: await r.json() });
  } catch(e) { res.status(502).json({ ok: false, error: e.message }); }
});

app.post('/cb/alerts', async (req, res) => {
  const { orgKey, apiId, apiSecret, cbUrl = 'https://defense.conferdeploy.net', since, limit = 100 } = req.body;
  try {
    const r = await fetch(`${cbUrl}/appservices/v6/orgs/${orgKey}/alerts/_search`, { method:'POST', headers:{'X-Auth-Token':`${apiSecret}/${apiId}`,'Content-Type':'application/json',Accept:'application/json'}, body: JSON.stringify({ criteria:{ create_time:{ start:since } }, sort:[{ field:'create_time', order:'DESC' }], rows:limit }) });
    res.json({ ok: r.ok, status: r.status, data: await r.json() });
  } catch(e) { res.status(502).json({ ok: false, error: e.message }); }
});

// ════════════════════════════════════════════════════════════════
// START
// ════════════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`\n✅ SENTINEL Proxy v3 — http://localhost:${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/health`);
  console.log(`   Mode:   ${process.env.ANTHROPIC_API_KEY ? '🤖 Claude AI (full intelligence)' : '🔧 Built-in engine + Live NVD/CISA feeds'}`);
  console.log(`\n   Open sentinel_soc.html in your browser.\n`);
});
