/**
 * SENTINEL SOC — EDR Proxy Server
 * Fixes CORS issues when calling EDR APIs (SentinelOne, CrowdStrike, Defender, Carbon Black)
 * from the browser.
 *
 * Usage:
 *   npm install express node-fetch cors
 *   node sentinel_proxy.js
 *
 * Then open sentinel_soc.html — it will automatically use this proxy on port 3847.
 */

const express  = require('express');
const cors     = require('cors');
const fetch    = (...args) => import('node-fetch').then(({default: f}) => f(...args));

const app  = express();
const PORT = 3847;

app.use(cors({ origin: '*' }));
app.use(express.json());

// ─── Health check ───────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// ─── SENTINEL Chat Engine ────────────────────────────────────────
// Multi-source threat intelligence chat. No API key required.
// Sources: MITRE ATT&CK, NVD/CVE, CISA advisories, built-in knowledge base.
app.post('/chat', async (req, res) => {
  const { question, alertCtx, sessionCtx, history = [] } = req.body;
  if (!question) return res.status(400).json({ error: 'question required' });

  try {
    // 1. Classify the question to know which sources to search
    const intent = classifyQuestion(question);

    // 2. Gather intelligence from relevant sources in parallel
    const [mitreData, cveData, cisaData] = await Promise.allSettled([
      intent.needsMitre ? searchMitre(question)  : Promise.resolve(null),
      intent.needsCve   ? searchNvd(question)     : Promise.resolve(null),
      intent.needsCisa  ? searchCisa(question)    : Promise.resolve(null),
    ]);

    const sources = {
      mitre: mitreData.status  === 'fulfilled' ? mitreData.value  : null,
      cve:   cveData.status    === 'fulfilled' ? cveData.value    : null,
      cisa:  cisaData.status   === 'fulfilled' ? cisaData.value   : null,
    };

    // 3. Build answer from gathered intelligence + built-in KB
    const answer = buildChatAnswer(question, intent, sources, alertCtx, sessionCtx, history);

    res.json({ answer, sources_searched: Object.keys(sources).filter(k => sources[k]) });
  } catch (err) {
    // Fallback to pure knowledge base if all searches fail
    const answer = buildChatAnswer(question, classifyQuestion(question), {}, alertCtx, sessionCtx, history);
    res.json({ answer });
  }
});

// ── Question classifier ──────────────────────────────────────────
function classifyQuestion(q) {
  const ql = q.toLowerCase();
  return {
    needsMitre: /mitre|att&?ck|technique|tactic|t\d{4}|ttp|kill.?chain|lateral|persistence|evasion|exfil|c2|command.control/.test(ql),
    needsCve:   /cve|vuln|exploit|patch|cve-\d|severity|cvss|zero.?day|rce|lpe|privilege/.test(ql),
    needsCisa:  /advisory|alert|ics|scada|known.exploit|kev|ransomware.group|apt|nation.state/.test(ql),
    isGeneral:  true,
    topic:      detectTopic(ql),
  };
}

function detectTopic(q) {
  if (/ransomware|encrypt|decrypt|ransom/.test(q))        return 'ransomware';
  if (/phishing|spear|email|attachment|macro/.test(q))    return 'phishing';
  if (/mimikatz|lsass|credential|dump|password/.test(q))  return 'credential_dump';
  if (/lateral|psexec|wmi|smb|rdp|pass.the/.test(q))      return 'lateral_movement';
  if (/persistence|scheduled.task|registry|autorun/.test(q)) return 'persistence';
  if (/defender|antivirus|edr|detection|bypass/.test(q))  return 'defense_evasion';
  if (/dns.tunnel|beacon|c2|command.control|cobalt/.test(q)) return 'c2';
  if (/log|siem|splunk|elastic|query|hunt/.test(q))        return 'threat_hunting';
  if (/isolat|contain|incident|respond|ir plan/.test(q))   return 'incident_response';
  if (/mitre|t\d{4}|ttp|technique/.test(q))               return 'mitre';
  if (/cve|vuln|patch|exploit/.test(q))                   return 'vulnerability';
  if (/apt|nation|group|actor|lazarus|cozy|fancy/.test(q)) return 'threat_actor';
  if (/ioc|indicator|hash|ip.block|domain.block/.test(q)) return 'ioc';
  return 'general';
}

// ── MITRE ATT&CK search ──────────────────────────────────────────
async function searchMitre(question) {
  const ql = question.toLowerCase();

  // Extract technique ID if present
  const techIdMatch = question.match(/T(\d{4})(?:\.(\d{3}))?/i);

  // Map keywords to MITRE technique details
  const TECHNIQUE_DB = {
    'T1003':   { name:'OS Credential Dumping',           tactic:'Credential Access',  url:'https://attack.mitre.org/techniques/T1003/', detail:'Adversaries attempt to dump credentials to obtain account login and credential material. Subtechniques include LSASS Memory (T1003.001), SAM (T1003.002), DCSync (T1003.006).' },
    'T1003.001':{ name:'LSASS Memory',                   tactic:'Credential Access',  url:'https://attack.mitre.org/techniques/T1003/001/', detail:'Adversaries access LSASS process memory to extract credentials. Tools: Mimikatz, ProcDump, Windows Task Manager. Detection: Event ID 4656/4663 on lsass.exe.' },
    'T1021.002':{ name:'SMB/Windows Admin Shares',       tactic:'Lateral Movement',   url:'https://attack.mitre.org/techniques/T1021/002/', detail:'Adversaries use valid accounts to interact with remote network shares via SMB. Tools: PsExec, Net commands, Cobalt Strike.' },
    'T1059.001':{ name:'PowerShell',                     tactic:'Execution',          url:'https://attack.mitre.org/techniques/T1059/001/', detail:'Adversaries abuse PowerShell for execution. Common: encoded commands (-enc), download cradles, AMSI bypass. Detection: Script block logging (Event 4104).' },
    'T1027':    { name:'Obfuscated Files or Information',tactic:'Defense Evasion',    url:'https://attack.mitre.org/techniques/T1027/', detail:'Adversaries obfuscate code/payloads to make analysis difficult. Includes Base64 encoding, XOR, custom packers.' },
    'T1053.005':{ name:'Scheduled Task',                 tactic:'Persistence',        url:'https://attack.mitre.org/techniques/T1053/005/', detail:'Adversaries abuse Windows Task Scheduler to execute programs at system startup or on a scheduled basis for persistence or privilege escalation.' },
    'T1562.001':{ name:'Disable or Modify Tools',        tactic:'Defense Evasion',    url:'https://attack.mitre.org/techniques/T1562/001/', detail:'Adversaries disable or modify security tools to avoid detection. Includes disabling Windows Defender via registry, tamper protection bypass.' },
    'T1071.004':{ name:'DNS',                            tactic:'Command and Control',url:'https://attack.mitre.org/techniques/T1071/004/', detail:'Adversaries use DNS for C2 communications. DNS tunneling encodes data in DNS queries/responses. Tools: dnscat2, iodine.' },
    'T1558.003':{ name:'Kerberoasting',                  tactic:'Credential Access',  url:'https://attack.mitre.org/techniques/T1558/003/', detail:'Adversaries request Kerberos TGS tickets for service accounts (SPNs) and crack offline. Tools: Rubeus, Impacket GetUserSPNs.' },
    'T1490':    { name:'Inhibit System Recovery',        tactic:'Impact',             url:'https://attack.mitre.org/techniques/T1490/', detail:'Adversaries delete shadow copies and backups before ransomware deployment. Common: vssadmin delete shadows /all /quiet.' },
    'T1486':    { name:'Data Encrypted for Impact',      tactic:'Impact',             url:'https://attack.mitre.org/techniques/T1486/', detail:'Adversaries encrypt data on target systems to disrupt availability. Ransomware groups: LockBit, BlackCat, Clop, Royal.' },
    'T1105':    { name:'Ingress Tool Transfer',          tactic:'Command and Control',url:'https://attack.mitre.org/techniques/T1105/', detail:'Adversaries transfer tools/files from external system to compromised environment. LOLBins: certutil, bitsadmin, mshta.' },
    'T1550.002':{ name:'Pass the Hash',                  tactic:'Lateral Movement',   url:'https://attack.mitre.org/techniques/T1550/002/', detail:'Adversaries use stolen NTLM password hashes to authenticate without plaintext password. Tools: Mimikatz pth, Impacket.' },
    'T1136.001':{ name:'Local Account',                  tactic:'Persistence',        url:'https://attack.mitre.org/techniques/T1136/001/', detail:'Adversaries create local accounts for persistent access. Detection: Event ID 4720 (account created), 4732 (added to admin group).' },
    'T1112':    { name:'Modify Registry',                tactic:'Defense Evasion',    url:'https://attack.mitre.org/techniques/T1112/', detail:'Adversaries modify registry to hide activity, persist, or disable security features.' },
    'T1566.001':{ name:'Spearphishing Attachment',       tactic:'Initial Access',     url:'https://attack.mitre.org/techniques/T1566/001/', detail:'Adversaries send spearphishing emails with malicious attachments (Office macros, PDFs, ISO files) as initial access vector.' },
    'T1047':    { name:'Windows Management Instrumentation', tactic:'Execution',      url:'https://attack.mitre.org/techniques/T1047/', detail:'Adversaries use WMI for execution, lateral movement, and persistence. Difficult to detect due to legitimate admin use.' },
    'T1041':    { name:'Exfiltration Over C2 Channel',   tactic:'Exfiltration',       url:'https://attack.mitre.org/techniques/T1041/', detail:'Adversaries steal data by exfiltrating it over an existing C2 channel to avoid detection of separate exfil connections.' },
  };

  // Find matching techniques
  const matches = [];
  if (techIdMatch) {
    const id = techIdMatch[0].toUpperCase();
    if (TECHNIQUE_DB[id]) matches.push({ id, ...TECHNIQUE_DB[id] });
    // also check parent
    const parent = id.split('.')[0];
    if (TECHNIQUE_DB[parent] && parent !== id) matches.push({ id: parent, ...TECHNIQUE_DB[parent] });
  }

  // Keyword match — reuse ql from top of function
  for (const [id, tech] of Object.entries(TECHNIQUE_DB)) {
    if (matches.find(m => m.id === id)) continue;
    if (ql.includes(tech.name.toLowerCase()) ||
        ql.includes(tech.tactic.toLowerCase()) ||
        tech.detail.toLowerCase().split(' ').some(w => w.length > 5 && ql.includes(w))) {
      matches.push({ id, ...tech });
    }
  }

  return matches.slice(0, 4);
}

// ── NVD/CVE search ───────────────────────────────────────────────
async function searchNvd(question) {
  // Extract CVE ID if directly mentioned
  const cveMatch = question.match(/CVE-\d{4}-\d+/i);
  if (cveMatch) {
    try {
      const cveId = cveMatch[0].toUpperCase();
      const r = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`, {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(5000),
      });
      if (!r.ok) return null;
      const data = await r.json();
      const vuln = data.vulnerabilities?.[0]?.cve;
      if (!vuln) return null;
      const cvss = vuln.metrics?.cvssMetricV31?.[0]?.cvssData || vuln.metrics?.cvssMetricV30?.[0]?.cvssData;
      return [{
        id:          cveId,
        description: vuln.descriptions?.find(d => d.lang === 'en')?.value || '',
        cvss:        cvss?.baseScore || 'N/A',
        severity:    cvss?.baseSeverity || 'N/A',
        published:   vuln.published?.split('T')[0] || '',
        url:         `https://nvd.nist.gov/vuln/detail/${cveId}`,
      }];
    } catch { return null; }
  }

  // General keyword search against NVD
  const keyword = question.replace(/[^\w\s]/g, ' ').trim().split(/\s+/).slice(0, 3).join(' ');
  try {
    const r = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=3`,
      { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(5000) }
    );
    if (!r.ok) return null;
    const data = await r.json();
    return (data.vulnerabilities || []).slice(0, 3).map(v => {
      const cve  = v.cve;
      const cvss = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV30?.[0]?.cvssData;
      return {
        id:          cve.id,
        description: cve.descriptions?.find(d => d.lang === 'en')?.value?.slice(0, 200) + '...' || '',
        cvss:        cvss?.baseScore || 'N/A',
        severity:    cvss?.baseSeverity || 'N/A',
        published:   cve.published?.split('T')[0] || '',
        url:         `https://nvd.nist.gov/vuln/detail/${cve.id}`,
      };
    });
  } catch { return null; }
}

// ── CISA KEV search ──────────────────────────────────────────────
async function searchCisa(question) {
  try {
    const r = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {
      signal: AbortSignal.timeout(6000),
    });
    if (!r.ok) return null;
    const data = await r.json();
    const ql = question.toLowerCase();

    // Search KEV catalog for relevant entries
    const hits = (data.vulnerabilities || [])
      .filter(v =>
        ql.includes(v.cveID?.toLowerCase()) ||
        v.product?.toLowerCase().split(/[\s\/]/).some(w => w.length > 3 && ql.includes(w)) ||
        v.vendorProject?.toLowerCase().split(/[\s\/]/).some(w => w.length > 3 && ql.includes(w)) ||
        v.shortDescription?.toLowerCase().split(' ').filter(w => w.length > 5).some(w => ql.includes(w))
      )
      .slice(0, 3)
      .map(v => ({
        id:          v.cveID,
        product:     `${v.vendorProject} ${v.product}`,
        description: v.shortDescription?.slice(0, 180) + '...',
        dueDate:     v.dueDate,
        ransomware:  v.knownRansomwareCampaignUse === 'Known',
        url:         `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
      }));

    return hits.length ? hits : null;
  } catch { return null; }
}

// ── Answer builder ───────────────────────────────────────────────
function buildChatAnswer(question, intent, sources, alertCtx, sessionCtx, history) {
  const topic = intent.topic;
  const mitre = sources.mitre || [];
  const cve   = sources.cve   || [];
  const cisa  = sources.cisa  || [];

  // Start with the core knowledge base answer for the topic
  let answer = buildTopicAnswer(question, topic, alertCtx, sessionCtx);

  // Append MITRE intelligence if found
  if (mitre.length) {
    answer += `\n<h3>📋 MITRE ATT&CK Intelligence</h3>`;
    mitre.forEach(t => {
      answer += `<div style="background:rgba(213,0,249,.07);border:1px solid rgba(213,0,249,.2);border-radius:5px;padding:8px 11px;margin-bottom:6px">
        <span class="mitre-pill">${t.id}</span> <strong>${t.name}</strong> — <em>${t.tactic}</em><br>
        <span style="font-size:11px;color:var(--text1)">${t.detail}</span><br>
        <a href="${t.url}" style="font-size:10px;color:var(--cyan)" target="_blank">→ ${t.url}</a>
      </div>`;
    });
  }

  // Append CVE data if found
  if (cve.length) {
    answer += `\n<h3>🔓 CVE / Vulnerability Data (NVD)</h3>`;
    cve.forEach(v => {
      const sevColor = { CRITICAL:'var(--red)', HIGH:'var(--orange2)', MEDIUM:'var(--yellow)', LOW:'var(--green)' }[v.severity] || 'var(--text1)';
      answer += `<div style="background:var(--bg3);border:1px solid var(--border2);border-radius:5px;padding:8px 11px;margin-bottom:6px">
        <strong style="color:var(--cyan)">${v.id}</strong>
        <span style="float:right;font-family:var(--mono);font-size:10px;color:${sevColor}">CVSS ${v.cvss} ${v.severity}</span><br>
        <span style="font-size:11px;color:var(--text1)">${v.description}</span><br>
        <span style="font-family:var(--mono);font-size:10px;color:var(--text3)">Published: ${v.published}</span>
        <a href="${v.url}" style="font-size:10px;color:var(--cyan);margin-left:10px" target="_blank">→ NVD</a>
      </div>`;
    });
  }

  // Append CISA KEV data if found
  if (cisa.length) {
    answer += `\n<h3>⚠ CISA Known Exploited Vulnerabilities</h3>`;
    cisa.forEach(v => {
      answer += `<div style="background:rgba(255,23,68,.07);border:1px solid rgba(255,23,68,.2);border-radius:5px;padding:8px 11px;margin-bottom:6px">
        <strong style="color:var(--red)">${v.id}</strong> — ${v.product}
        ${v.ransomware ? ' <span style="background:rgba(255,23,68,.2);color:var(--red);font-size:9px;padding:1px 6px;border-radius:3px;font-family:var(--mono)">RANSOMWARE</span>' : ''}<br>
        <span style="font-size:11px;color:var(--text1)">${v.description}</span><br>
        <span style="font-family:var(--mono);font-size:10px;color:var(--text3)">CISA patch deadline: ${v.dueDate}</span>
        <a href="${v.url}" style="font-size:10px;color:var(--cyan);margin-left:10px" target="_blank">→ Details</a>
      </div>`;
    });
  }

  return answer.trim();
}

// ── Topic-specific knowledge base answers ───────────────────────
function buildTopicAnswer(question, topic, alertCtx, sessionCtx) {
  const ctx = alertCtx ? `<div style="background:rgba(0,229,255,.06);border-left:2px solid var(--cyan);padding:6px 10px;margin-bottom:10px;font-size:11px;font-family:var(--mono)">🔗 Alert context: ${alertCtx}</div>` : '';
  const sessionInfo = sessionCtx ? `<div style="background:rgba(0,229,255,.04);border-left:2px solid var(--border2);padding:5px 10px;margin-bottom:10px;font-size:10px;font-family:var(--mono);color:var(--text2)">${sessionCtx}</div>` : '';

  const KB = {
    credential_dump: `${ctx}${sessionInfo}
<strong>Credential Dumping</strong> is one of the most critical post-exploitation activities. Attackers extract credentials to enable lateral movement and privilege escalation.<br><br>
<strong>Common techniques:</strong>
<ul>
  <li><strong>LSASS dump:</strong> Mimikatz, ProcDump, Task Manager, comsvcs.dll</li>
  <li><strong>SAM database:</strong> reg save HKLM\\SAM + SYSTEM hive</li>
  <li><strong>DCSync:</strong> Impersonate a DC to replicate password hashes</li>
  <li><strong>NTDS.dit:</strong> Extract domain hashes directly from Domain Controller</li>
</ul>
<strong>Detection commands:</strong>
<div class="cmd">Get-WinEvent -FilterHashtable @{LogName='Security';Id=4656} | Where {$_.Message -like '*lsass*'}</div>
<div class="cmd">Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} | Where {$_.Message -like '*Type 9*'}</div>
<strong>Immediate response:</strong>
<ul>
  <li>Isolate endpoint, force password reset on ALL accounts that touched this host</li>
  <li>Enable Credential Guard: Group Policy → Device Guard → Credential Guard</li>
  <li>Enable Protected Users security group for privileged accounts</li>
  <li>Block LSASS access via Attack Surface Reduction rule: <code>9e6c4e1f-7d60-472f-ba1a-a39ef669e4b3</code></li>
</ul>`,

    lateral_movement: `${ctx}${sessionInfo}
<strong>Lateral Movement</strong> is how attackers spread from an initial foothold to high-value targets.<br><br>
<strong>Top techniques observed in real incidents:</strong>
<ul>
  <li><strong>Pass-the-Hash (T1550.002):</strong> Use NTLM hash without knowing plaintext password</li>
  <li><strong>PsExec / SMB (T1021.002):</strong> Execute remote commands via admin shares</li>
  <li><strong>WMI (T1047):</strong> <code>wmic /node:TARGET process call create "cmd /c..."</code></li>
  <li><strong>RDP (T1021.001):</strong> Abuse stolen credentials with RDP</li>
  <li><strong>Cobalt Strike Beacon:</strong> SMB/TCP beacons for C2 + lateral movement</li>
</ul>
<strong>Hunt queries:</strong>
<div class="cmd">Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} | Where {$_.Message -like '*Logon Type:		3*'}</div>
<div class="cmd">Get-WinEvent -FilterHashtable @{LogName='System';Id=7045} | Select TimeCreated,Message</div>
<strong>Block lateral movement:</strong>
<ul>
  <li>Segment network — workstations should not reach other workstations on port 445</li>
  <li>Disable NTLM where possible, enforce Kerberos</li>
  <li>Local Administrator Password Solution (LAPS) to prevent hash reuse</li>
</ul>`,

    ransomware: `${ctx}${sessionInfo}
<strong>Ransomware Response — Time is critical.</strong><br><br>
<strong>Immediate actions (first 15 minutes):</strong>
<ul>
  <li>🚨 Isolate ALL affected hosts from the network NOW</li>
  <li>Do NOT reboot — memory forensics may be lost</li>
  <li>Preserve disk images before any recovery</li>
  <li>Contact IR retainer + cyber insurance immediately</li>
</ul>
<strong>Common pre-ransomware indicators to hunt:</strong>
<ul>
  <li>VSS deletion: <code>vssadmin delete shadows</code>, <code>wmic shadowcopy delete</code></li>
  <li>Backup tampering, antivirus disabling</li>
  <li>Mass SMB connections to file shares</li>
  <li>Cobalt Strike / Metasploit beacons in process list</li>
  <li>Net discovery commands: <code>net view /all</code>, <code>nltest /dclist</code></li>
</ul>
<strong>Active ransomware groups (2024-2025):</strong> LockBit 3.0, BlackCat/ALPHV, Clop, Play, Black Basta, Akira, Royal<br><br>
<strong>Recovery sequence:</strong> Contain → Eradicate → Restore from clean backup → Patch entry point → Monitor`,

    phishing: `${ctx}${sessionInfo}
<strong>Phishing remains the #1 initial access vector.</strong><br><br>
<strong>Detection indicators:</strong>
<ul>
  <li>Office process spawning cmd.exe, powershell.exe, wscript.exe, mshta.exe</li>
  <li>winword.exe / excel.exe making network connections</li>
  <li>ISO / IMG / ZIP attachments with LNK files (post Mark-of-the-Web bypass)</li>
  <li>Newly registered domains in email headers</li>
</ul>
<strong>Hunt for macro execution:</strong>
<div class="cmd">Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} | Where {$_.Message -like '*winword*powershell*'}</div>
<strong>Containment:</strong>
<ul>
  <li>Block sender domain at email gateway immediately</li>
  <li>Search all mailboxes for same subject/sender: use M365 Content Search or Google Vault</li>
  <li>Identify all users who opened the attachment</li>
  <li>Isolate any endpoint where attachment was opened</li>
</ul>`,

    persistence: `${ctx}${sessionInfo}
<strong>Persistence Mechanisms</strong> — attackers establish these to survive reboots and credential resets.<br><br>
<strong>Most common persistence locations:</strong>
<ul>
  <li><strong>Registry Run Keys:</strong> <code>HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</code></li>
  <li><strong>Scheduled Tasks:</strong> <code>schtasks /query /fo LIST /v</code></li>
  <li><strong>Services:</strong> Event ID 7045 — new service installed</li>
  <li><strong>Startup folder:</strong> <code>%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup</code></li>
  <li><strong>WMI subscriptions:</strong> Stealthy, survives most cleanup</li>
  <li><strong>DLL hijacking:</strong> Replace legitimate DLL in app directory</li>
</ul>
<strong>Audit all persistence at once (Autoruns):</strong>
<div class="cmd">autorunsc.exe -a * -c -h -s -u > autoruns_output.csv</div>
<div class="cmd">Get-ScheduledTask | Where State -ne 'Disabled' | Select TaskName,TaskPath,State | Export-Csv tasks.csv</div>`,

    defense_evasion: `${ctx}${sessionInfo}
<strong>Defense Evasion</strong> — attackers actively work to avoid detection.<br><br>
<strong>Common techniques observed:</strong>
<ul>
  <li><strong>AV/EDR Tamper:</strong> Registry disable, service stop, process injection into security tools</li>
  <li><strong>LOLBins:</strong> certutil, mshta, regsvr32, rundll32, msiexec for payload delivery</li>
  <li><strong>AMSI Bypass:</strong> Patch amsi.dll in memory to neutralize script scanning</li>
  <li><strong>ETW Patching:</strong> Blind event tracing to hide malicious activity</li>
  <li><strong>Process Hollowing / Injection:</strong> Hide malicious code in legitimate processes</li>
</ul>
<strong>Detect LOLBin abuse:</strong>
<div class="cmd">Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} | Where {$_.Message -match 'certutil|mshta|regsvr32|wscript'}</div>
<strong>Re-enable Defender if tampered:</strong>
<div class="cmd">Set-MpPreference -DisableRealtimeMonitoring $false</div>
<div class="cmd">reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0 /f</div>`,

    c2: `${ctx}${sessionInfo}
<strong>Command & Control (C2)</strong> detection and disruption.<br><br>
<strong>Common C2 frameworks seen in the wild:</strong>
<ul>
  <li><strong>Cobalt Strike:</strong> Most common. Beacon uses HTTP/HTTPS/DNS/SMB. Detection: Hunt for named pipes <code>\\pipe\\MSSE-*</code></li>
  <li><strong>Sliver:</strong> Open-source, mTLS/WireGuard/HTTP3 channels</li>
  <li><strong>Brute Ratel:</strong> EDR evasion focused, used by nation-state actors</li>
  <li><strong>DNS tunneling:</strong> dnscat2, iodine — high query volume, long subdomain names</li>
</ul>
<strong>Hunt for suspicious beacons:</strong>
<div class="cmd">netstat -ano | findstr ESTABLISHED | findstr ":443"</div>
<div class="cmd">Get-NetTCPConnection -State Established | Where {$_.RemotePort -in @(443,80,8080,8443)} | Select LocalAddress,RemoteAddress,OwningProcess</div>
<strong>Block C2:</strong>
<ul>
  <li>Null-route the C2 domain/IP at DNS and firewall</li>
  <li>Isolate host before blocking to prevent adversary alert</li>
  <li>Capture memory image for IOC extraction first</li>
</ul>`,

    threat_hunting: `${ctx}${sessionInfo}
<strong>Threat Hunting</strong> — proactive search for hidden threats.<br><br>
<strong>High-value hunts to run now:</strong>
<ul>
  <li><strong>Beacon detection:</strong> Processes making periodic outbound connections</li>
  <li><strong>LOLBin abuse:</strong> certutil, mshta, regsvr32 with network activity</li>
  <li><strong>Pass-the-Hash:</strong> NTLM auth (Event 4624 Type 9) from workstations</li>
  <li><strong>Kerberoasting:</strong> TGS-REQ spike — many SPNs in short time</li>
  <li><strong>Scheduled task creation:</strong> Event 4698 — tasks created by non-admin users</li>
</ul>
<strong>Quick Splunk/KQL starter hunts:</strong>
<div class="cmd">index=wineventlog EventCode=4688 process_name IN ("certutil.exe","mshta.exe","regsvr32.exe") | stats count by host, process_name, parent_process_name</div>
<div class="cmd">// KQL — Defender: DeviceProcessEvents | where FileName in ("certutil.exe","mshta.exe") | project Timestamp, DeviceName, FileName, ProcessCommandLine</div>`,

    incident_response: `${ctx}${sessionInfo}
<strong>Incident Response Framework</strong> — structured approach to handling security incidents.<br><br>
<strong>IR Phases (NIST SP 800-61):</strong>
<ul>
  <li><strong>1. Preparation:</strong> IR plan, runbooks, contact list, tooling ready</li>
  <li><strong>2. Detection & Analysis:</strong> Confirm incident, scope, initial triage</li>
  <li><strong>3. Containment:</strong> Short-term (isolate), long-term (block vectors)</li>
  <li><strong>4. Eradication:</strong> Remove malware, close entry points, patch</li>
  <li><strong>5. Recovery:</strong> Restore systems, monitor for reinfection</li>
  <li><strong>6. Post-Incident:</strong> Lessons learned, update detections, report</li>
</ul>
<strong>First 30 minutes checklist:</strong>
<ul>
  <li>☐ Confirm incident is real (not false positive)</li>
  <li>☐ Identify affected scope (hosts, users, data)</li>
  <li>☐ Activate IR team + notify management</li>
  <li>☐ Preserve evidence (logs, memory, disk)</li>
  <li>☐ Contain — isolate affected systems</li>
  <li>☐ Begin timeline reconstruction</li>
</ul>`,

    threat_actor: `${ctx}${sessionInfo}
<strong>Threat Actor Intelligence</strong><br><br>
<strong>Active APT groups (2024-2025):</strong>
<ul>
  <li><strong>Lazarus Group (North Korea):</strong> Financial theft, crypto attacks, supply chain. TTPs: custom loaders, macOS malware</li>
  <li><strong>APT29 / Cozy Bear (Russia):</strong> Espionage focus, cloud environments, OAuth abuse, SVR-linked</li>
  <li><strong>APT41 (China):</strong> Dual espionage + cybercrime, supply chain, healthcare, telco</li>
  <li><strong>Scattered Spider:</strong> Social engineering, SIM swapping, cloud-focused, MGM breach actor</li>
  <li><strong>ALPHV/BlackCat:</strong> Ransomware-as-a-Service, multi-extortion, healthcare focus</li>
</ul>
<strong>Intelligence sources to monitor:</strong>
<ul>
  <li><a href="https://attack.mitre.org/groups/" style="color:var(--cyan)" target="_blank">MITRE ATT&CK Groups</a></li>
  <li><a href="https://www.cisa.gov/news-events/cybersecurity-advisories" style="color:var(--cyan)" target="_blank">CISA Advisories</a></li>
  <li><a href="https://otx.alienvault.com" style="color:var(--cyan)" target="_blank">AlienVault OTX</a></li>
  <li><a href="https://www.virustotal.com" style="color:var(--cyan)" target="_blank">VirusTotal</a></li>
</ul>`,

    ioc: `${ctx}${sessionInfo}
<strong>IOC Management & Blocking</strong><br><br>
<strong>Where to block IOCs:</strong>
<ul>
  <li><strong>File hashes:</strong> EDR custom block policy, AV signatures</li>
  <li><strong>IP addresses:</strong> Firewall outbound block, proxy deny list</li>
  <li><strong>Domains:</strong> DNS sinkhole, proxy category block, firewall FQDN rule</li>
  <li><strong>URLs:</strong> Proxy / web gateway block list</li>
  <li><strong>Email indicators:</strong> Mail gateway sender/domain block</li>
</ul>
<strong>Free IOC lookup sources:</strong>
<ul>
  <li><a href="https://www.virustotal.com" style="color:var(--cyan)" target="_blank">VirusTotal</a> — hashes, IPs, domains</li>
  <li><a href="https://otx.alienvault.com" style="color:var(--cyan)" target="_blank">AlienVault OTX</a> — threat pulses</li>
  <li><a href="https://www.abuseipdb.com" style="color:var(--cyan)" target="_blank">AbuseIPDB</a> — malicious IPs</li>
  <li><a href="https://urlhaus.abuse.ch" style="color:var(--cyan)" target="_blank">URLhaus</a> — malware URLs</li>
  <li><a href="https://bazaar.abuse.ch" style="color:var(--cyan)" target="_blank">MalwareBazaar</a> — file samples</li>
</ul>`,

    vulnerability: `${ctx}${sessionInfo}
<strong>Vulnerability Intelligence</strong><br><br>
<strong>Prioritization framework:</strong>
<ul>
  <li><strong>CISA KEV first:</strong> Known exploited vulns must be patched within CISA deadline</li>
  <li><strong>CVSS 9.0+ with public exploit:</strong> Patch within 24-48 hours</li>
  <li><strong>CVSS 7.0-8.9:</strong> Patch within 7-14 days</li>
  <li><strong>Below 7.0:</strong> Standard patch cycle</li>
</ul>
<strong>Key resources:</strong>
<ul>
  <li><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" style="color:var(--cyan)" target="_blank">CISA KEV Catalog</a></li>
  <li><a href="https://nvd.nist.gov" style="color:var(--cyan)" target="_blank">NIST NVD</a></li>
  <li><a href="https://www.exploit-db.com" style="color:var(--cyan)" target="_blank">Exploit-DB</a></li>
</ul>`,

    general: `${ctx}${sessionInfo}
I'm SENTINEL, your cybersecurity SOC assistant. I can help with:<br><br>
<ul>
  <li>🔍 <strong>Threat analysis</strong> — explain any EDR alert in detail</li>
  <li>⚔ <strong>MITRE ATT&CK mapping</strong> — techniques, tactics, procedures</li>
  <li>🛡 <strong>Incident response</strong> — step-by-step containment guidance</li>
  <li>🔓 <strong>CVE lookups</strong> — vulnerability details from NVD (live)</li>
  <li>🚨 <strong>CISA KEV</strong> — known exploited vulnerabilities (live)</li>
  <li>🔎 <strong>Threat hunting</strong> — detection queries and hunt hypotheses</li>
  <li>👥 <strong>Threat actors</strong> — APT profiles and campaign tracking</li>
</ul>
Ask me anything — for example: <em>"What is Kerberoasting and how do I detect it?"</em> or <em>"Explain T1059.001"</em> or <em>"How do I respond to a ransomware incident?"</em>`,
  };

  return KB[topic] || KB.general;
}

// ─── AI endpoint — routes chat vs alert analysis ─────────────────
app.post('/ai', async (req, res) => {
  const { messages, system, max_tokens = 1500 } = req.body;
  if (!messages || !messages.length) return res.status(400).json({ error: 'messages required' });

  const userPrompt = messages.filter(m => m.role === 'user').pop()?.content || '';

  try {
    // Real Claude API if key is present
    if (process.env.ANTHROPIC_API_KEY) {
      const upstream = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type':      'application/json',
          'anthropic-version': '2023-06-01',
          'x-api-key':         process.env.ANTHROPIC_API_KEY,
        },
        body: JSON.stringify({ model:'claude-sonnet-4-20250514', max_tokens, ...(system?{system}:{}), messages }),
      });
      const data = await upstream.json();
      return res.status(upstream.status).json(data);
    }

    // Built-in engine: detect whether this is an alert analysis or a chat message
    const isAlertAnalysis = userPrompt.includes('Title:') && userPrompt.includes('Severity:') && userPrompt.includes('Raw Event:');
    const text = isAlertAnalysis ? analyzeAlert(userPrompt) : respondToChat(userPrompt, messages, system || '');

    return res.json({
      id: 'sentinel-local-' + Date.now(),
      type: 'message', role: 'assistant',
      content: [{ type: 'text', text }],
      model: 'sentinel-local-engine',
      stop_reason: 'end_turn',
    });
  } catch (err) {
    res.status(502).json({ error: { message: err.message } });
  }
});

// ─── Chat response engine ─────────────────────────────────────────
// Handles free-form SOC chat questions without any external API.
function respondToChat(question, messages, systemCtx) {
  const q = question.toLowerCase().trim();

  // Extract alert context injected by the system prompt
  const alertCtx  = systemCtx.match(/Active alert context:\s*"([^"]+)"/)?.[1] || null;
  const severityCtx = systemCtx.match(/severity\s+(\w+)/i)?.[1] || null;

  // ── Greetings ──
  if (/^(hi|hello|hey|good\s*(morning|afternoon|evening)|howdy)[\s!?.]*$/.test(q)) {
    return `Hello! I'm SENTINEL, your SOC assistant. I can help you with:
<ul>
  <li><strong>Threat analysis</strong> — select any alert on the left for a full breakdown</li>
  <li><strong>MITRE ATT&CK</strong> — ask about any technique (e.g. "what is T1059?")</li>
  <li><strong>Investigation steps</strong> — ask how to investigate any alert type</li>
  <li><strong>Remediation guidance</strong> — containment steps for any threat</li>
  <li><strong>IOC lookups</strong> — ask about any hash, IP, or process</li>
</ul>
What are you investigating today?`;
  }

  // ── Help / capabilities ──
  if (/what can you do|help|capabilities|features/.test(q)) {
    return `I'm your built-in SOC assistant. Here's what I can do:
<ul>
  <li>Explain any <strong>alert or threat type</strong> in plain language</li>
  <li>Map activity to <strong>MITRE ATT&CK techniques</strong> (ask "what is T1003" for example)</li>
  <li>Give step-by-step <strong>investigation commands</strong> for Windows/Linux</li>
  <li>Provide <strong>containment and remediation</strong> guidance</li>
  <li>Explain attack concepts like lateral movement, persistence, C2, exfiltration</li>
  <li>Help interpret <strong>IOCs</strong> — hashes, IPs, registry keys, processes</li>
  <li>Guide you through <strong>incident response</strong> procedures</li>
</ul>
Select an alert for full AI analysis, or just ask me anything.`;
  }

  // ── Active alert context questions ──
  if (alertCtx && /this alert|current alert|selected alert|what happened|explain this|tell me more|what does this mean/.test(q)) {
    const cat = detectCategory(alertCtx.toLowerCase());
    return `Based on the currently selected alert — <strong>"${alertCtx}"</strong> (${severityCtx || 'HIGH'} severity):
<p>This alert indicates ${CATEGORY_EXPLAIN[cat] || CATEGORY_EXPLAIN.persistence}. Click <strong>Re-analyze</strong> in the center panel to get the full structured breakdown including MITRE mapping, investigation commands, and containment steps.</p>
<p>Or ask me a specific question — for example: <em>"How do I investigate this?"</em> or <em>"What MITRE techniques apply?"</em></p>`;
  }

  if (alertCtx && /how do i investigate|investigate this|investigation steps|what should i check/.test(q)) {
    const cat = detectCategory(alertCtx.toLowerCase() + ' ' + q);
    const tmpl = RESPONSE_TEMPLATES[cat] || RESPONSE_TEMPLATES.persistence;
    return `<strong>Investigation steps for "${alertCtx}":</strong>
<ul>${tmpl.investigation.map((s,i) => `<li><strong>${i+1}.</strong> ${s}</li>`).join('')}</ul>`;
  }

  if (alertCtx && /contain|isolat|remediat|how do i stop|what do i do|response steps/.test(q)) {
    const cat = detectCategory(alertCtx.toLowerCase() + ' ' + q);
    const tmpl = RESPONSE_TEMPLATES[cat] || RESPONSE_TEMPLATES.persistence;
    return `<strong>Containment steps for "${alertCtx}":</strong>
<ul>${tmpl.containment.map((s,i) => `<li><strong>${i+1}.</strong> ${s}</li>`).join('')}</ul>`;
  }

  // ── MITRE technique lookup ──
  const mitreId = q.match(/t(\d{4})(?:\.(\d{3}))?/i);
  if (mitreId || /mitre|att&ck|technique|tactic/.test(q)) {
    return respondMITRE(q, mitreId);
  }

  // ── Specific threat topic questions ──
  if (/lsass|credential dump|mimikatz|sekurlsa/.test(q))
    return chatThreatExplain('credential', q);
  if (/lateral movement|psexec|pass.the.hash|pth|wmi|smb pivot/.test(q))
    return chatThreatExplain('lateral', q);
  if (/ransomware|encrypt|vssadmin|shadow cop/.test(q))
    return chatThreatExplain('impact', q);
  if (/persistenc|scheduled task|run key|startup|schtask|autorun/.test(q))
    return chatThreatExplain('persistence', q);
  if (/powershell|encoded|base64|obfuscat|lolbin|living off/.test(q))
    return chatThreatExplain('defense_evasion', q);
  if (/dns tunnel|c2|command and control|beacon|cobalt|exfil/.test(q))
    return chatThreatExplain('c2', q);
  if (/kerberoast|rubeus|spn|ticket|kerberos/.test(q))
    return respondKerberoast();
  if (/phishing|spearphish|macro|word.*doc|excel.*macro/.test(q))
    return respondPhishing();
  if (/isolat|contain|network block|firewall rule/.test(q))
    return respondContainment();
  if (/log.*analys|event.*log|siem|splunk|event id/.test(q))
    return respondLogAnalysis();
  if (/ioc|indicator|hash|sha256|md5|ip address|malicious ip/.test(q))
    return respondIOC(q);
  if (/report|weekly|summary|pdf|download/.test(q))
    return `To generate a report, click the <strong>📄 Report</strong> tab on the right panel. Choose your report type and click <strong>Generate Report</strong>. You can then download it as HTML, Markdown, CSV, or JSON. Make sure you have alerts loaded first.`;
  if (/how.*(start|begin|use|work)|getting started|setup/.test(q))
    return respondGettingStarted();
  if (/what is|explain|define|meaning of|tell me about/.test(q))
    return respondWhatIs(q);
  if (/endpoint|host|machine|workstation|server/.test(q) && /isolat|disconnect|block/.test(q))
    return respondIsolation();

  // ── Fallback: keyword-driven general response ──
  return respondGeneral(q, alertCtx);
}

// ── Topic responders ──────────────────────────────────────────────
const CATEGORY_EXPLAIN = {
  credential:      'credential theft or dumping is in progress — an attacker is attempting to steal authentication material (passwords, hashes, tokens) to enable further access',
  lateral:         'an attacker is moving laterally through the network — they have compromised one host and are attempting to reach others, typically targeting domain controllers or file servers',
  persistence:     'a persistence mechanism is being established — the attacker is ensuring they maintain access to the system even after reboots or credential changes',
  defense_evasion: 'the attacker is attempting to disable or evade security controls — this typically precedes the primary attack payload and means an intrusion is likely already in progress',
  c2:              'an active Command & Control channel has been established — the attacker can remotely control the compromised host, exfiltrate data, or deploy additional payloads',
  impact:          'a destructive or high-impact attack is underway — this may include ransomware, data wiping, or mass file encryption',
};

function detectCategory(text) {
  if (/lsass|mimikatz|credential|hash|kerbero|dump/.test(text)) return 'credential';
  if (/psexec|lateral|smb|wmi|remote service/.test(text))       return 'lateral';
  if (/ransom|encrypt|vssadmin|shadow/.test(text))              return 'impact';
  if (/defender|disabl|evasion|certutil|lolbin/.test(text))     return 'defense_evasion';
  if (/dns|tunnel|c2|beacon|exfil/.test(text))                  return 'c2';
  return 'persistence';
}

function chatThreatExplain(cat, q) {
  const explanations = {
    credential: `<strong>Credential Dumping</strong> is the process of extracting authentication credentials from a compromised system.
<p><strong>Common tools:</strong> <code>mimikatz</code>, <code>procdump</code>, Task Manager (lsass dump), <code>Invoke-Mimikatz</code></p>
<p><strong>Primary targets:</strong> LSASS process memory (passwords, NTLM hashes, Kerberos tickets), SAM database, NTDS.dit (Active Directory)</p>
<p><strong>Why it matters:</strong> Once credentials are stolen, the attacker can move laterally without triggering further alerts — they appear as legitimate users.</p>
<p><strong>Key MITRE techniques:</strong> <span class="mitre-pill">T1003.001</span> LSASS Memory &nbsp; <span class="mitre-pill">T1558.003</span> Kerberoasting &nbsp; <span class="mitre-pill">T1550.002</span> Pass-the-Hash</p>
<p><strong>Quick detection check:</strong></p>
<div class="cmd">Get-WinEvent -FilterHashtable @{LogName='Security';Id=4656} | Where-Object {$_.Message -match 'lsass'} | Select -First 20</div>`,

    lateral: `<strong>Lateral Movement</strong> is when an attacker pivots from an initially compromised host to other systems on the network.
<p><strong>Common techniques:</strong> PsExec (SMB), WMI execution, RDP, Pass-the-Hash, Pass-the-Ticket, token impersonation</p>
<p><strong>What to look for:</strong> Logon Type 3 (network logon) from unexpected sources, new service installations, ADMIN$ share access</p>
<p><strong>Key MITRE techniques:</strong> <span class="mitre-pill">T1021.002</span> SMB/Admin Shares &nbsp; <span class="mitre-pill">T1047</span> WMI &nbsp; <span class="mitre-pill">T1550.002</span> Pass-the-Hash</p>
<p><strong>Quick detection:</strong></p>
<div class="cmd">Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} | Where-Object {$_.Message -match 'LogonType.*3'} | Select -First 20</div>`,

    impact: `<strong>Ransomware / Destructive Attack</strong> — this is the most critical alert type. Immediate action is required.
<p><strong>Indicators:</strong> VSS deletion (<code>vssadmin delete shadows</code>), mass file renaming, ransom note creation, high disk I/O across file shares</p>
<p><strong>🚨 Immediate actions:</strong></p>
<ul>
  <li>Disconnect ALL affected hosts from the network NOW</li>
  <li>Do NOT reboot — this may destroy forensic evidence</li>
  <li>Contact your IR team and cyber insurance immediately</li>
  <li>Preserve disk images before any recovery attempt</li>
</ul>
<p><strong>Key MITRE techniques:</strong> <span class="mitre-pill">T1486</span> Data Encrypted for Impact &nbsp; <span class="mitre-pill">T1490</span> Inhibit System Recovery</p>`,

    defense_evasion: `<strong>Defense Evasion</strong> techniques are used to avoid detection and bypass security controls.
<p><strong>Common methods:</strong> Disabling AV/EDR, obfuscated PowerShell (<code>-EncodedCommand</code>), LOLBins (certutil, mshta, regsvr32), process injection, timestomping</p>
<p><strong>Why it's critical:</strong> Defense evasion almost always means an attack is already in progress. The attacker is clearing the path for their primary objective.</p>
<p><strong>Key MITRE techniques:</strong> <span class="mitre-pill">T1562.001</span> Disable Security Tools &nbsp; <span class="mitre-pill">T1027</span> Obfuscation &nbsp; <span class="mitre-pill">T1140</span> Deobfuscate/Decode</p>
<p><strong>Check Defender status:</strong></p>
<div class="cmd">Get-MpComputerStatus | Select RealTimeProtectionEnabled, AntivirusEnabled, BehaviorMonitorEnabled</div>`,

    c2: `<strong>Command & Control (C2)</strong> is the communication channel between a compromised host and the attacker's infrastructure.
<p><strong>Common C2 channels:</strong> HTTPS beacons (Cobalt Strike, Metasploit), DNS tunneling, HTTP over legitimate services (Teams, Slack, GitHub)</p>
<p><strong>DNS tunneling specifically:</strong> Data is encoded into DNS query subdomains. Hard to detect with basic monitoring because DNS is often trusted.</p>
<p><strong>Key MITRE techniques:</strong> <span class="mitre-pill">T1071.001</span> Web Protocols &nbsp; <span class="mitre-pill">T1071.004</span> DNS &nbsp; <span class="mitre-pill">T1573</span> Encrypted Channel</p>
<p><strong>Find suspicious DNS queries:</strong></p>
<div class="cmd">Get-DnsClientCache | Where-Object {$_.Entry.Length -gt 30} | Sort-Object Entry -Descending | Select -First 20</div>`,
  };
  return explanations[cat] || explanations.credential;
}

function respondMITRE(q, idMatch) {
  const MITRE_DETAIL = {
    'T1003':     { name:'OS Credential Dumping',              tactic:'Credential Access', desc:'Adversaries attempt to dump credentials to obtain account login and credential material. Targets include LSASS, SAM, NTDS.dit, and cached credentials.' },
    'T1003.001': { name:'LSASS Memory',                       tactic:'Credential Access', desc:'Extracting credentials from the Local Security Authority Subsystem Service (LSASS) process memory using tools like Mimikatz or procdump.' },
    'T1021.002': { name:'SMB/Windows Admin Shares',           tactic:'Lateral Movement',  desc:'Using Windows file sharing protocol (SMB) and admin shares (ADMIN$, C$) to move laterally, often with PsExec or similar tools.' },
    'T1059.001': { name:'PowerShell',                         tactic:'Execution',          desc:'Using PowerShell for malicious execution, often with encoded commands (-EncodedCommand) or download cradles (IEX, Invoke-WebRequest).' },
    'T1027':     { name:'Obfuscated Files or Information',    tactic:'Defense Evasion',   desc:'Encoding or encrypting payloads to evade detection. Common techniques include Base64 encoding, XOR, and string concatenation.' },
    'T1053.005': { name:'Scheduled Task',                     tactic:'Persistence',        desc:'Creating scheduled tasks to execute malicious programs at startup or on a schedule. Uses schtasks.exe or Task Scheduler API.' },
    'T1562.001': { name:'Disable or Modify Security Tools',   tactic:'Defense Evasion',   desc:'Disabling AV, EDR, or Windows Defender via registry, Group Policy, service manipulation, or process termination.' },
    'T1486':     { name:'Data Encrypted for Impact',          tactic:'Impact',             desc:'Encrypting files to make them inaccessible — the primary ransomware technique. Often preceded by shadow copy deletion.' },
    'T1490':     { name:'Inhibit System Recovery',            tactic:'Impact',             desc:'Deleting shadow copies (vssadmin), backup catalogs, or disabling recovery features to prevent restoration after ransomware.' },
    'T1071.004': { name:'Application Layer Protocol: DNS',    tactic:'C2',                 desc:'Using DNS queries/responses for C2 communication or data exfiltration, encoding data in subdomains or TXT records.' },
    'T1558.003': { name:'Kerberoasting',                      tactic:'Credential Access', desc:'Requesting Kerberos TGS tickets for service accounts and cracking them offline to obtain plaintext passwords.' },
    'T1550.002': { name:'Pass the Hash',                      tactic:'Lateral Movement',  desc:'Using stolen NTLM hashes to authenticate without knowing the plaintext password, bypassing normal login.' },
    'T1105':     { name:'Ingress Tool Transfer',              tactic:'C2',                 desc:'Transferring tools or payloads from external infrastructure to a compromised host using certutil, bitsadmin, PowerShell, etc.' },
    'T1112':     { name:'Modify Registry',                    tactic:'Defense Evasion',   desc:'Modifying registry keys to maintain persistence, disable security tools, or change system behavior.' },
    'T1136.001': { name:'Create Local Account',               tactic:'Persistence',        desc:'Creating local user accounts to maintain persistent access, often adding them to the Administrators group.' },
    'T1566.001': { name:'Spearphishing Attachment',           tactic:'Initial Access',     desc:'Sending targeted phishing emails with malicious attachments (Word/Excel macros, PDFs, ISOs) to gain initial access.' },
    'T1047':     { name:'Windows Management Instrumentation', tactic:'Execution',          desc:'Using WMI for execution, lateral movement, and persistence. Hard to detect as it uses legitimate Windows infrastructure.' },
  };

  if (idMatch) {
    const full  = `T${idMatch[1]}${idMatch[2] ? '.'+idMatch[2] : ''}`.toUpperCase();
    const short = `T${idMatch[1]}`;
    const detail = MITRE_DETAIL[full] || MITRE_DETAIL[short];
    if (detail) {
      return `<strong><span class="mitre-pill">${full}</span> ${detail.name}</strong>
<p><strong>Tactic:</strong> ${detail.tactic}</p>
<p>${detail.desc}</p>
<p><strong>Reference:</strong> <code>https://attack.mitre.org/techniques/${full.replace('.','/')}/</code></p>`;
    }
    return `<span class="mitre-pill">${full}</span> — I don't have details on that specific technique in my local knowledge base. Check the full reference at: <code>https://attack.mitre.org/techniques/${full}/</code>`;
  }

  // Generic MITRE question
  return `<strong>MITRE ATT&CK</strong> is a globally accessible knowledge base of adversary tactics and techniques based on real-world observations.
<p>It's organized into <strong>14 Tactics</strong> (the "why" — e.g. Initial Access, Execution, Persistence) and hundreds of <strong>Techniques</strong> (the "how" — e.g. T1059 PowerShell).</p>
<p><strong>Common tactics in order of attack progression:</strong></p>
<ul>
  <li><strong>Initial Access</strong> — Phishing, exploit public-facing app</li>
  <li><strong>Execution</strong> — PowerShell, WMI, scheduled tasks</li>
  <li><strong>Persistence</strong> — Registry run keys, scheduled tasks, new accounts</li>
  <li><strong>Defense Evasion</strong> — Disable AV, obfuscation, LOLBins</li>
  <li><strong>Credential Access</strong> — LSASS dump, Kerberoasting, keylogging</li>
  <li><strong>Lateral Movement</strong> — PsExec, Pass-the-Hash, RDP</li>
  <li><strong>Exfiltration</strong> — Compressed archives, DNS tunneling, HTTPS</li>
  <li><strong>Impact</strong> — Ransomware, data destruction, service disruption</li>
</ul>
Ask me about any specific technique ID (e.g. <em>"what is T1003"</em>) for details.`;
}

function respondKerberoast() {
  return `<strong>Kerberoasting</strong> <span class="mitre-pill">T1558.003</span>
<p>An attacker with any domain user account requests Kerberos TGS service tickets for accounts with Service Principal Names (SPNs), then cracks them offline to get plaintext passwords.</p>
<p><strong>Why it works:</strong> Any domain user can request service tickets — no special privileges needed. The ticket is encrypted with the service account's password hash, which can be cracked offline with Hashcat or John.</p>
<p><strong>Detection:</strong></p>
<div class="cmd">Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} | Where-Object {$_.Message -match 'RC4'} | Select -First 20</div>
<p><strong>Indicators:</strong> Event ID 4769 with encryption type 0x17 (RC4) from an account making many TGS requests in a short period.</p>
<p><strong>Mitigation:</strong> Use AES encryption for service accounts, enforce long complex passwords (25+chars) for service accounts, use Group Managed Service Accounts (gMSA).</p>`;
}

function respondPhishing() {
  return `<strong>Phishing / Macro-based Initial Access</strong> <span class="mitre-pill">T1566.001</span>
<p>Malicious Office documents (Word/Excel) with embedded macros are the most common initial access vector. When the user enables macros, the VBA code executes — typically downloading a payload or spawning PowerShell.</p>
<p><strong>Attack chain:</strong> Email → User opens doc → Enables macros → VBA spawns <code>cmd.exe</code> or <code>powershell.exe</code> → Payload downloads → C2 established</p>
<p><strong>Detection — suspicious parent processes:</strong></p>
<div class="cmd">Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} | Where-Object {$_.Message -match 'winword|excel|powerpnt'} | Select -First 10</div>
<p><strong>Block macros via Group Policy:</strong> Computer Config → Admin Templates → Microsoft Office → Security Settings → Disable all macros</p>`;
}

function respondContainment() {
  return `<strong>Endpoint Isolation / Containment Steps</strong>
<p>When you need to contain a compromised host:</p>
<ul>
  <li><strong>Via EDR console:</strong> Use your EDR's "Isolate Host" or "Network Containment" feature — this is the fastest method</li>
  <li><strong>Via Windows Firewall (emergency):</strong></li>
</ul>
<div class="cmd">netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound</div>
<ul>
  <li><strong>Via Active Directory:</strong> Disable the computer account in AD to prevent re-authentication</li>
  <li><strong>Via switch/VLAN:</strong> Contact network team to move the port to an isolated VLAN</li>
</ul>
<p><strong>After isolation:</strong></p>
<ul>
  <li>Preserve memory image before any changes: <div class="cmd">winpmem_mini_x64.exe memdump.raw</div></li>
  <li>Collect EDR telemetry and event logs before remediation</li>
  <li>Document the exact time of isolation for the incident timeline</li>
</ul>`;
}

function respondLogAnalysis() {
  return `<strong>Windows Event Log Analysis — Key Event IDs</strong>
<ul>
  <li><strong>4624</strong> — Successful logon (check Logon Type: 3=network, 10=remote interactive)</li>
  <li><strong>4625</strong> — Failed logon (brute force indicator)</li>
  <li><strong>4648</strong> — Logon with explicit credentials (lateral movement indicator)</li>
  <li><strong>4656/4663</strong> — Object access (file/process handle requests)</li>
  <li><strong>4688</strong> — Process creation (enable command line logging via GPO)</li>
  <li><strong>4698</strong> — Scheduled task created</li>
  <li><strong>4720/4732</strong> — Account created / added to group</li>
  <li><strong>7045</strong> — New service installed</li>
  <li><strong>4769</strong> — Kerberos service ticket request</li>
</ul>
<p><strong>Query recent logon events:</strong></p>
<div class="cmd">Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=(Get-Date).AddHours(-24)} | Select TimeCreated,Message | Format-List</div>
<p><strong>Enable process command line logging (essential for threat hunting):</strong></p>
<div class="cmd">auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable</div>`;
}

function respondIOC(q) {
  return `<strong>IOC (Indicator of Compromise) Analysis</strong>
<p>IOCs are artifacts that indicate a system may have been compromised. Common types:</p>
<ul>
  <li><strong>File hashes</strong> (MD5, SHA256) — search in VirusTotal, MalwareBazaar</li>
  <li><strong>IP addresses</strong> — check in AbuseIPDB, GreyNoise, Shodan</li>
  <li><strong>Domains</strong> — check in URLhaus, Cisco Talos, VirusTotal</li>
  <li><strong>Registry keys</strong> — document and compare against baseline</li>
  <li><strong>Process names/paths</strong> — verify digital signatures and expected locations</li>
</ul>
<p><strong>Check file hash on a system:</strong></p>
<div class="cmd">Get-FileHash "C:\\path\\to\\file.exe" -Algorithm SHA256 | Select Hash</div>
<p><strong>Block a hash in Windows Defender:</strong></p>
<div class="cmd">Add-MpPreference -ThreatIDDefaultAction_Ids 2147519003 -ThreatIDDefaultAction_Actions Block</div>
<p><strong>Free IOC lookup resources:</strong> VirusTotal.com, AbuseIPDB.com, MalwareBazaar.abuse.ch, URLhaus.abuse.ch, GreyNoise.io</p>`;
}

function respondIsolation() {
  return `<strong>Isolating an Endpoint — Step by Step</strong>
<ol>
  <li><strong>Via EDR (preferred):</strong> In your SentinelOne/CrowdStrike console → find the host → click "Isolate" or "Network Containment". This blocks all traffic except EDR communication.</li>
  <li><strong>Manually via firewall:</strong>
    <div class="cmd">netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound</div>
  </li>
  <li><strong>Disconnect from Active Directory:</strong> Disable the computer account in AD so it can't re-authenticate after reconnection.</li>
  <li><strong>Physical:</strong> As last resort — unplug the network cable or disable the NIC.</li>
</ol>
<p><strong>Before isolating:</strong> Make sure you can still communicate with the host (e.g., via out-of-band management or EDR agent) to collect evidence.</p>
<p><strong>After isolating:</strong> Take a memory dump, export event logs, and collect EDR telemetry before starting remediation.</p>`;
}

function respondGettingStarted() {
  return `<strong>Getting Started with SENTINEL SOC</strong>
<ol>
  <li><strong>Select your EDR platform</strong> from the dropdown on the left panel</li>
  <li>For <strong>Demo Mode</strong>: click Test Connection → Start Monitoring right away</li>
  <li>For <strong>real EDR</strong>: enter your API credentials → Test Connection → Start Monitoring</li>
  <li>Once alerts load, <strong>click any alert</strong> to get full AI analysis</li>
  <li>Use the <strong>Chat tab</strong> (here) for questions, <strong>Stats tab</strong> for overview, <strong>Report tab</strong> for reports</li>
</ol>
<p>The system fetches alerts from the past 7 days by default (configurable) and polls for new alerts on your chosen interval.</p>`;
}

function respondWhatIs(q) {
  const topics = {
    'edr':        'EDR (Endpoint Detection and Response) is security software that monitors endpoints (computers, servers) for suspicious activity, records behavioral telemetry, and enables investigation and response. Examples: CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint.',
    'soc':        'A SOC (Security Operations Center) is a team of security analysts that monitors, detects, investigates, and responds to cybersecurity threats 24/7. SENTINEL is a tool to assist SOC analysts.',
    'ioc':        'An IOC (Indicator of Compromise) is a piece of forensic evidence that suggests a system has been breached — such as a malicious file hash, suspicious IP address, or unusual registry key.',
    'apt':        'An APT (Advanced Persistent Threat) is a sophisticated, long-term cyberattack by a well-resourced adversary (often nation-state) who gains access to a network and remains undetected for extended periods.',
    'zero day':   'A zero-day is a software vulnerability that is unknown to the vendor and has no patch available. Attackers exploit it before defenses can be developed.',
    'privilege escalation': 'Privilege Escalation is when an attacker gains higher-level permissions than initially obtained — for example, going from a standard user to Administrator or SYSTEM.',
    'threat hunting': 'Threat Hunting is the proactive search for threats that have evaded existing security controls, rather than waiting for alerts. Hunters use hypotheses based on TTPs to find hidden malicious activity.',
  };

  for (const [key, val] of Object.entries(topics)) {
    if (q.includes(key)) return `<strong>${key.toUpperCase()}</strong><p>${val}</p>`;
  }

  return respondGeneral(q, null);
}

function respondGeneral(q, alertCtx) {
  const suggestions = [
    'Try asking about a specific threat: <em>"explain lateral movement"</em>, <em>"what is ransomware"</em>, <em>"how does kerberoasting work"</em>',
    'Ask for investigation steps: <em>"how do I investigate a PowerShell alert"</em>',
    'Ask about MITRE techniques: <em>"what is T1059"</em>, <em>"explain T1003"</em>',
    'Ask for containment steps: <em>"how do I isolate an endpoint"</em>',
    'Ask about log analysis: <em>"what Windows event IDs should I check"</em>',
  ];

  if (alertCtx) {
    return `I'm not sure what you're asking, but I can see you have <strong>"${alertCtx}"</strong> selected. Try asking:
<ul>
  <li><em>"How do I investigate this alert?"</em></li>
  <li><em>"What containment steps should I take?"</em></li>
  <li><em>"What MITRE techniques does this map to?"</em></li>
</ul>`;
  }

  return `I'm your SOC assistant — I specialize in cybersecurity topics. ${suggestions[Math.floor(Math.random() * suggestions.length)]}
<p>Or select an alert from the left panel and I'll provide full analysis automatically.</p>`;
}

// ─── AI Analysis endpoint — no API key needed ────────────────────
// Performs structured threat analysis entirely server-side using
// a built-in MITRE ATT&CK knowledge base and rule engine.
app.post('/ai', async (req, res) => {
  const { messages, system, max_tokens = 1500 } = req.body;
  if (!messages || !messages.length) return res.status(400).json({ error: 'messages required' });

  // Extract the user prompt (last user message)
  const prompt = messages.filter(m => m.role === 'user').pop()?.content || '';

  try {
    // If ANTHROPIC_API_KEY is set, use the real API
    if (process.env.ANTHROPIC_API_KEY) {
      const upstream = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type':      'application/json',
          'anthropic-version': '2023-06-01',
          'x-api-key':         process.env.ANTHROPIC_API_KEY,
        },
        body: JSON.stringify({
          model: 'claude-sonnet-4-20250514',
          max_tokens,
          ...(system ? { system } : {}),
          messages,
        }),
      });
      const data = await upstream.json();
      return res.status(upstream.status).json(data);
    }

    // ── Built-in analysis engine (no API key required) ───────────
    const analysis = analyzeAlert(prompt);
    return res.json({
      id: 'sentinel-local-' + Date.now(),
      type: 'message',
      role: 'assistant',
      content: [{ type: 'text', text: analysis }],
      model: 'sentinel-local-engine',
      stop_reason: 'end_turn',
    });

  } catch (err) {
    res.status(502).json({ error: { message: err.message } });
  }
});

// ─── Built-in threat analysis engine ─────────────────────────────
const MITRE = {
  'lsass':         { id:'T1003.001', name:'OS Credential Dumping: LSASS Memory',    tactic:'Credential Access' },
  'mimikatz':      { id:'T1003.001', name:'OS Credential Dumping: LSASS Memory',    tactic:'Credential Access' },
  'sekurlsa':      { id:'T1003.001', name:'OS Credential Dumping: LSASS Memory',    tactic:'Credential Access' },
  'psexec':        { id:'T1021.002', name:'Remote Services: SMB/Windows Admin Shares', tactic:'Lateral Movement' },
  'psexesvc':      { id:'T1021.002', name:'Remote Services: SMB/Windows Admin Shares', tactic:'Lateral Movement' },
  'powershell':    { id:'T1059.001', name:'Command and Scripting Interpreter: PowerShell', tactic:'Execution' },
  '-enc':          { id:'T1027',     name:'Obfuscated Files or Information',         tactic:'Defense Evasion' },
  'base64':        { id:'T1027',     name:'Obfuscated Files or Information',         tactic:'Defense Evasion' },
  'schtasks':      { id:'T1053.005', name:'Scheduled Task/Job: Scheduled Task',      tactic:'Persistence' },
  'scheduled task':{ id:'T1053.005', name:'Scheduled Task/Job: Scheduled Task',      tactic:'Persistence' },
  'defender':      { id:'T1562.001', name:'Impair Defenses: Disable or Modify Tools', tactic:'Defense Evasion' },
  'disableantispyware': { id:'T1562.001', name:'Impair Defenses: Disable or Modify Tools', tactic:'Defense Evasion' },
  'dns tunnel':    { id:'T1071.004', name:'Application Layer Protocol: DNS',         tactic:'Command and Control' },
  'dns tunneling': { id:'T1071.004', name:'Application Layer Protocol: DNS',         tactic:'Command and Control' },
  'kerberoast':    { id:'T1558.003', name:'Steal or Forge Kerberos Tickets: Kerberoasting', tactic:'Credential Access' },
  'rubeus':        { id:'T1558.003', name:'Steal or Forge Kerberos Tickets: Kerberoasting', tactic:'Credential Access' },
  'vssadmin':      { id:'T1490',     name:'Inhibit System Recovery',                 tactic:'Impact' },
  'shadow':        { id:'T1490',     name:'Inhibit System Recovery',                 tactic:'Impact' },
  'ransomware':    { id:'T1486',     name:'Data Encrypted for Impact',               tactic:'Impact' },
  'encrypt':       { id:'T1486',     name:'Data Encrypted for Impact',               tactic:'Impact' },
  'certutil':      { id:'T1105',     name:'Ingress Tool Transfer',                   tactic:'Command and Control' },
  'pass-the-hash': { id:'T1550.002', name:'Use Alternate Authentication Material: Pass the Hash', tactic:'Lateral Movement' },
  'pth':           { id:'T1550.002', name:'Use Alternate Authentication Material: Pass the Hash', tactic:'Lateral Movement' },
  'taskmgr':       { id:'T1003',     name:'OS Credential Dumping',                   tactic:'Credential Access' },
  'net user':      { id:'T1136.001', name:'Create Account: Local Account',           tactic:'Persistence' },
  'registry':      { id:'T1112',     name:'Modify Registry',                         tactic:'Defense Evasion' },
  'winword':       { id:'T1566.001', name:'Phishing: Spearphishing Attachment',      tactic:'Initial Access' },
  'macro':         { id:'T1059.005', name:'Command and Scripting Interpreter: Visual Basic', tactic:'Execution' },
  'wmi':           { id:'T1047',     name:'Windows Management Instrumentation',      tactic:'Execution' },
  'smb':           { id:'T1021.002', name:'Remote Services: SMB/Windows Admin Shares', tactic:'Lateral Movement' },
  'ntlm':          { id:'T1550.002', name:'Use Alternate Authentication Material',   tactic:'Lateral Movement' },
  'lateral':       { id:'T1021',     name:'Remote Services',                         tactic:'Lateral Movement' },
  'exfil':         { id:'T1041',     name:'Exfiltration Over C2 Channel',            tactic:'Exfiltration' },
  'download':      { id:'T1105',     name:'Ingress Tool Transfer',                   tactic:'Command and Control' },
  'persistence':   { id:'T1547',     name:'Boot or Logon Autostart Execution',       tactic:'Persistence' },
  'run key':       { id:'T1547.001', name:'Registry Run Keys / Startup Folder',      tactic:'Persistence' },
};

const RESPONSE_TEMPLATES = {
  credential: {
    investigation: [
      'Check Security event log for Event ID 4624 (logon) and 4648 (explicit credentials)',
      'Review LSASS access history: <div class="cmd">Get-WinEvent -FilterHashtable @{LogName="Security";Id=4656} | Where-Object {$_.Message -like "*lsass*"}</div>',
      'List all processes with handles to lsass.exe: <div class="cmd">Get-Process | Where-Object {$_.Modules -like "*lsass*"}</div>',
      'Check for credential files or dumps on disk: <div class="cmd">Get-ChildItem C:\\ -Recurse -Include *.dmp,*.dump -ErrorAction SilentlyContinue</div>',
      'Review recently created files in temp directories: <div class="cmd">Get-ChildItem $env:TEMP -Newer (Get-Date).AddHours(-2)</div>',
    ],
    containment: [
      'Isolate the endpoint from the network immediately via EDR console',
      'Force password reset for ALL accounts that logged into this endpoint in the past 30 days',
      'Revoke and re-issue any service account tokens used on this host',
      'Enable Credential Guard if not already active (requires reboot)',
      'Review all active sessions: <div class="cmd">qwinsta /server:HOSTNAME</div>',
    ],
  },
  lateral: {
    investigation: [
      'Map all connections from the source host: <div class="cmd">netstat -ano | findstr ESTABLISHED</div>',
      'Check Windows Event logs for remote logon activity (Event ID 4624, Logon Type 3)',
      'Review SMB share access logs on all target systems',
      'Identify all systems this host communicated with in past 24 hours via EDR telemetry',
      'Check for new services installed: <div class="cmd">Get-WinEvent -FilterHashtable @{LogName="System";Id=7045} | Select-Object TimeCreated,Message</div>',
    ],
    containment: [
      'Isolate both the source AND target endpoints',
      'Block SMB (port 445) between workstation segments at the firewall',
      'Disable the compromised account and force re-authentication',
      'Remove any remotely installed services: <div class="cmd">sc delete PSEXESVC</div>',
      'Review and restrict local admin accounts across the environment',
    ],
  },
  persistence: {
    investigation: [
      'List all scheduled tasks: <div class="cmd">schtasks /query /fo LIST /v | findstr "Task Name\\|Status\\|Run As User"</div>',
      'Check autorun registry keys: <div class="cmd">reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</div>',
      'Review startup folder contents: <div class="cmd">Get-ChildItem "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"</div>',
      'Check for new services created in the last 24 hours via Event ID 7045',
      'Hash the suspicious binary and check against VirusTotal',
    ],
    containment: [
      'Delete the identified scheduled task: <div class="cmd">schtasks /delete /tn "\\TASKNAME" /f</div>',
      'Remove malicious registry run key: <div class="cmd">reg delete HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "ValueName" /f</div>',
      'Quarantine the binary via EDR before deletion',
      'Block the file hash at EDR/AV policy level',
      'Audit all other endpoints for the same task/binary',
    ],
  },
  defense_evasion: {
    investigation: [
      'Check Windows Defender status: <div class="cmd">Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled</div>',
      'Review registry for security tool modifications: <div class="cmd">reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"</div>',
      'Check audit log for gaps (disabled logging = red flag)',
      'List all processes running without AV: <div class="cmd">Get-Process | Where-Object {$_.Path -ne $null} | Select-Object Name,Path</div>',
      'Check for LOLBin execution: certutil, mshta, regsvr32, rundll32 in process history',
    ],
    containment: [
      'Re-enable Windows Defender via Group Policy immediately',
      'Restore registry key: <div class="cmd">reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0 /f</div>',
      'Force a full AV scan: <div class="cmd">Start-MpScan -ScanType FullScan</div>',
      'Alert SOC team — defense evasion often signals an active intrusion in progress',
      'Check what activity occurred during the window AV was disabled',
    ],
  },
  c2: {
    investigation: [
      'Capture full DNS query logs from the affected host for the past 24 hours',
      'Analyze query patterns: length, frequency, entropy of subdomain strings',
      'Identify the process making DNS requests: <div class="cmd">Get-Process -Id (Get-NetUDPEndpoint -LocalPort 53).OwningProcess</div>',
      'Block and sinkhole the suspicious domain at DNS/firewall level',
      'Check for encoded data in HTTP/DNS traffic with Wireshark or EDR network telemetry',
    ],
    containment: [
      'Block all outbound DNS to external resolvers — force use of internal DNS only',
      'Add the malicious domain to your DNS blackhole / firewall block list',
      'Isolate the host to prevent further C2 communication',
      'Capture a memory image for forensic analysis before isolating',
      'Review all other hosts communicating with the same destination IP',
    ],
  },
  impact: {
    investigation: [
      'Immediately check scope: how many files are encrypted?',
      'Identify patient zero — which host started the encryption?',
      'Check VSS status: <div class="cmd">vssadmin list shadows</div>',
      'Review backup integrity — assume backups are targeted',
      'Preserve a disk image of affected systems for forensics BEFORE any recovery attempt',
    ],
    containment: [
      '🚨 CRITICAL: Disconnect ALL affected hosts from the network immediately',
      'Do NOT reboot affected systems — this may destroy forensic evidence',
      'Isolate backup systems and verify their integrity',
      'Contact your incident response retainer / cyber insurance provider NOW',
      'Preserve all logs and EDR telemetry before any remediation',
    ],
  },
};

function analyzeAlert(prompt) {
  const p = prompt.toLowerCase();

  // Detect MITRE techniques
  const matched = new Map();
  for (const [keyword, tech] of Object.entries(MITRE)) {
    if (p.includes(keyword)) matched.set(tech.id, tech);
  }
  const techniques = [...matched.values()].slice(0, 5);

  // Detect category for response template
  let category = 'persistence';
  if (p.includes('lsass') || p.includes('mimikatz') || p.includes('credential') || p.includes('hash') || p.includes('kerbero') || p.includes('dump')) category = 'credential';
  else if (p.includes('psexec') || p.includes('lateral') || p.includes('smb') || p.includes('wmi') || p.includes('remote')) category = 'lateral';
  else if (p.includes('defender') || p.includes('disabl') || p.includes('evasion') || p.includes('certutil') || p.includes('lolbin')) category = 'defense_evasion';
  else if (p.includes('dns') || p.includes('tunnel') || p.includes('c2') || p.includes('beacon') || p.includes('exfil')) category = 'c2';
  else if (p.includes('ransom') || p.includes('encrypt') || p.includes('vssadmin') || p.includes('shadow')) category = 'impact';

  const tmpl = RESPONSE_TEMPLATES[category] || RESPONSE_TEMPLATES.persistence;

  // Extract alert fields from prompt
  const titleMatch   = prompt.match(/Title:\s*(.+)/);
  const sevMatch     = prompt.match(/Severity:\s*(\w+)/);
  const endpointMatch= prompt.match(/Endpoint:\s*(.+)/);
  const userMatch    = prompt.match(/User:\s*(.+)/);
  const processMatch = prompt.match(/Process:\s*(.+)/);
  const rawMatch     = prompt.match(/Raw Event:\s*(.+)/);

  const title    = titleMatch?.[1]?.trim()    || 'Security Alert';
  const severity = sevMatch?.[1]?.trim()      || 'HIGH';
  const endpoint = endpointMatch?.[1]?.trim() || 'Unknown';
  const user     = userMatch?.[1]?.trim()     || 'Unknown';
  const process  = processMatch?.[1]?.trim()  || 'Unknown';
  const rawEvent = rawMatch?.[1]?.trim()       || '';

  const sevEmoji = { CRITICAL:'🔴', HIGH:'🟠', MEDIUM:'🟡', LOW:'🟢' }[severity] || '🟠';

  const mitreHtml = techniques.length
    ? techniques.map(t => `<span class="mitre-pill">${t.id}</span> <strong>${t.name}</strong> — ${t.tactic}`).join('<br>')
    : '<span class="mitre-pill">T1059</span> <strong>Command and Scripting Interpreter</strong> — Execution';

  const investSteps = tmpl.investigation.map((s,i) => `<li><strong>Step ${i+1}:</strong> ${s}</li>`).join('');
  const containSteps = tmpl.containment.map((s,i) => `<li><strong>${i+1}.</strong> ${s}</li>`).join('');

  const iocLines = [];
  const iocMatch = prompt.match(/IoCs:\s*(.+)/);
  if (iocMatch) iocLines.push(...iocMatch[1].split('|').map(s => s.trim()).filter(Boolean));

  const iocBlock = iocLines.length
    ? iocLines.map(i => `<li>Add to EDR block policy: <code>${i}</code></li>`).join('')
    : '<li>Block process hash at EDR policy level</li><li>Add C2 IPs/domains to firewall blocklist</li>';

  // Kill chain context
  const killChain = {
    credential: 'This activity is consistent with <strong>post-exploitation credential harvesting</strong>. The attacker likely already has a foothold on the system (Initial Access + Execution complete). Dumping credentials enables lateral movement to higher-value targets like domain controllers. If uncontained, expect Pass-the-Hash or Pass-the-Ticket attacks within minutes to hours.',
    lateral: 'This indicates an <strong>active lateral movement campaign</strong>. The attacker has compromised at least one host and is pivoting to others. This often follows credential theft. Expect the attacker to be targeting privileged accounts and critical infrastructure. Time is critical — every minute risks additional host compromise.',
    persistence: 'This is a <strong>persistence mechanism</strong> being established, suggesting the attacker intends to maintain long-term access. This typically follows initial access and execution. The attacker is preparing for continued operations — exfiltration, ransomware deployment, or espionage. Look for earlier-stage activity in your logs.',
    defense_evasion: 'Defense evasion typically signals an <strong>active intrusion in progress</strong>. Attackers disable security tools immediately before executing their primary objective (data theft, ransomware, lateral movement). Treat this as a critical precursor — the main attack payload has likely already been deployed or is imminent.',
    c2: 'This indicates an <strong>active Command & Control channel</strong>. The attacker has established persistent communication with the compromised host. Data exfiltration, remote command execution, and malware updates are all possible. The longer this channel stays open, the greater the data loss risk.',
    impact: '🚨 <strong>This is an active ransomware/destructive attack.</strong> Business continuity is at immediate risk. Containment must happen within minutes. Standard IR procedures apply but time is the critical variable. Activate your incident response plan immediately.',
  };

  return `
<h3>🎯 What Happened</h3>
<p>The EDR detected <strong>${title}</strong> on endpoint <code>${endpoint}</code> (user: <code>${user}</code>). The activity was triggered by <code>${process}</code>. ${rawEvent ? `Specifically: ${rawEvent}` : 'This pattern matches known threat actor techniques and requires immediate investigation.'}</p>

<h3>💥 Impact & Risk</h3>
<p>${sevEmoji} <strong>${severity} severity.</strong> ${killChain[category] || killChain.persistence}</p>

<h3>⚔ MITRE ATT&CK Mapping</h3>
<p>${mitreHtml}</p>

<h3>🔗 Attack Chain Context</h3>
<p>${killChain[category] || killChain.persistence}</p>

<h3>🔍 Investigation Steps</h3>
<ul>${investSteps}</ul>

<h3>🛡 Containment Guidance</h3>
<ul>${containSteps}</ul>

<h3>🔒 IOC Blocking</h3>
<ul>${iocBlock}</ul>
`.trim();
}

// ─── Universal proxy endpoint ────────────────────────────────────
// POST /proxy  { url, method, headers, body }
app.post('/proxy', async (req, res) => {
  const { url, method = 'GET', headers = {}, body } = req.body;

  if (!url) return res.status(400).json({ error: 'url is required' });

  // Safety: only allow known EDR domains
  const allowed = [
    'sentinelone.net',
    'crowdstrike.com',
    'api.securitycenter.microsoft.com',
    'login.microsoftonline.com',
    'conferdeploy.net',
    'carbonblack.vmware.com',
  ];
  const isAllowed = allowed.some(d => url.includes(d));
  if (!isAllowed) return res.status(403).json({ error: 'Domain not allowed' });

  try {
    const fetchOpts = { method, headers };
    if (body) fetchOpts.body = typeof body === 'string' ? body : JSON.stringify(body);

    const upstream = await fetch(url, fetchOpts);
    const contentType = upstream.headers.get('content-type') || '';

    let data;
    if (contentType.includes('application/json')) {
      data = await upstream.json();
    } else {
      data = await upstream.text();
    }

    res.status(upstream.status).json({
      status: upstream.status,
      ok: upstream.ok,
      data,
    });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// ─── SentinelOne shortcuts ───────────────────────────────────────
app.post('/s1/test', async (req, res) => {
  const { token, baseUrl } = req.body;
  if (!token || !baseUrl) return res.status(400).json({ error: 'token and baseUrl required' });
  try {
    const r = await fetch(`${baseUrl}/web/api/v2.1/system/status`, {
      headers: { Authorization: `ApiToken ${token}`, Accept: 'application/json' }
    });
    const data = await r.json();
    res.json({ ok: r.ok, status: r.status, data });
  } catch(e) {
    res.status(502).json({ ok: false, error: e.message });
  }
});

app.post('/s1/threats', async (req, res) => {
  const { token, baseUrl, since, limit = 100 } = req.body;
  if (!token || !baseUrl) return res.status(400).json({ error: 'token and baseUrl required' });
  try {
    const url = `${baseUrl}/web/api/v2.1/threats?createdAt__gte=${since}&limit=${limit}&sortBy=createdAt&sortOrder=desc`;
    const r = await fetch(url, {
      headers: { Authorization: `ApiToken ${token}`, Accept: 'application/json' }
    });
    const data = await r.json();
    res.json({ ok: r.ok, status: r.status, data });
  } catch(e) {
    res.status(502).json({ ok: false, error: e.message });
  }
});

// ─── CrowdStrike shortcuts ───────────────────────────────────────
app.post('/cs/auth', async (req, res) => {
  const { clientId, clientSecret, baseUrl = 'https://api.crowdstrike.com' } = req.body;
  try {
    const r = await fetch(`${baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: `client_id=${encodeURIComponent(clientId)}&client_secret=${encodeURIComponent(clientSecret)}`
    });
    const data = await r.json();
    res.json({ ok: r.ok, status: r.status, data });
  } catch(e) {
    res.status(502).json({ ok: false, error: e.message });
  }
});

app.post('/cs/detections', async (req, res) => {
  const { token, baseUrl = 'https://api.crowdstrike.com', since, limit = 100 } = req.body;
  try {
    // 1. Query IDs
    const qr = await fetch(
      `${baseUrl}/detects/queries/detects/v1?filter=created_timestamp:>='${since}'&limit=${limit}&sort=created_timestamp.desc`,
      { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' } }
    );
    const qd = await qr.json();
    const ids = (qd.resources || []).slice(0, 50);
    if (!ids.length) return res.json({ ok: true, data: { resources: [] } });

    // 2. Fetch details
    const dr = await fetch(`${baseUrl}/detects/entities/summaries/GET/v1`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids })
    });
    const dd = await dr.json();
    res.json({ ok: dr.ok, status: dr.status, data: dd });
  } catch(e) {
    res.status(502).json({ ok: false, error: e.message });
  }
});

// ─── Microsoft Defender shortcuts ───────────────────────────────
app.post('/mde/auth', async (req, res) => {
  const { tenantId, clientId, clientSecret } = req.body;
  try {
    const r = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `client_id=${encodeURIComponent(clientId)}&client_secret=${encodeURIComponent(clientSecret)}&scope=https://api.securitycenter.microsoft.com/.default&grant_type=client_credentials`
    });
    const data = await r.json();
    res.json({ ok: r.ok, status: r.status, data });
  } catch(e) {
    res.status(502).json({ ok: false, error: e.message });
  }
});

app.post('/mde/alerts', async (req, res) => {
  const { token, since, limit = 100 } = req.body;
  try {
    const r = await fetch(
      `https://api.securitycenter.microsoft.com/api/alerts?$filter=alertCreationTime ge ${since}&$orderby=alertCreationTime desc&$top=${limit}`,
      { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' } }
    );
    const data = await r.json();
    res.json({ ok: r.ok, status: r.status, data });
  } catch(e) {
    res.status(502).json({ ok: false, error: e.message });
  }
});

// ─── Carbon Black shortcuts ──────────────────────────────────────
app.post('/cb/alerts', async (req, res) => {
  const { orgKey, apiId, apiSecret, cbUrl = 'https://defense.conferdeploy.net', since, limit = 100 } = req.body;
  try {
    const r = await fetch(`${cbUrl}/appservices/v6/orgs/${orgKey}/alerts/_search`, {
      method: 'POST',
      headers: {
        'X-Auth-Token': `${apiSecret}/${apiId}`,
        'Content-Type': 'application/json', Accept: 'application/json'
      },
      body: JSON.stringify({
        criteria: { create_time: { start: since } },
        sort: [{ field: 'create_time', order: 'DESC' }],
        rows: limit
      })
    });
    const data = await r.json();
    res.json({ ok: r.ok, status: r.status, data });
  } catch(e) {
    res.status(502).json({ ok: false, error: e.message });
  }
});

app.listen(PORT, () => {
  console.log(`\n✅ SENTINEL Proxy running on http://localhost:${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/health\n`);
  if (process.env.ANTHROPIC_API_KEY) {
    console.log(`✅ Anthropic API key detected — using Claude AI for analysis.\n`);
  } else {
    console.log(`✅ No API key needed — using built-in threat analysis engine.`);
    console.log(`   (Optional: set ANTHROPIC_API_KEY env var for Claude-powered analysis)\n`);
  }
  console.log(`   Open sentinel_soc.html in your browser.\n`);
});
