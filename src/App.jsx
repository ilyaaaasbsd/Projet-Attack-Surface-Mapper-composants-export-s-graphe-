import React, { useState, useRef, useEffect, useCallback } from "react";

// ── Mermaid CDN loader ──────────────────────────────────────────────────────
function useMermaid() {
  const [ready, setReady] = useState(false);
  useEffect(() => {
    if (window.mermaid) { setReady(true); return; }
    const s = document.createElement("script");
    s.src = "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js";
    s.onload = () => {
      window.mermaid.initialize({ 
        startOnLoad: false, 
        theme: "dark", 
        darkMode: true,
        fontFamily: "'JetBrains Mono', monospace",
        themeVariables: { 
          primaryColor: "#1e293b", 
          primaryTextColor: "#e2e8f0",
          lineColor: "#4ade80", 
          nodeBorder: "#334155", 
          mainBkg: "#0f172a",
          fontSize: "14px"
        } 
      });
      setReady(true);
    };
    document.head.appendChild(s);
  }, []);
  return ready;
}

// ── Constants & Helpers ─────────────────────────────────────────────────────
const SEV = {
  CRITICAL: { bg: "#450a0a", border: "#dc2626", text: "#fca5a5", dot: "#ef4444" },
  HIGH:     { bg: "#431407", border: "#ea580c", text: "#fdba74", dot: "#f97316" },
  MEDIUM:   { bg: "#422006", border: "#d97706", text: "#fcd34d", dot: "#fbbf24" },
  LOW:      { bg: "#052e16", border: "#16a34a", text: "#86efac", dot: "#4ade80" },
};

const SAMPLE_MANIFEST = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.vulnerableapp"
    android:allowBackup="true"
    android:debuggable="true">

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />

    <application android:label="VulnApp" android:theme="@style/AppTheme">

        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>

        <activity android:name=".DeepLinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="vulnapp" android:host="open"/>
            </intent-filter>
        </activity>

        <activity android:name=".AdminActivity" android:exported="true"/>

        <service android:name=".DataSyncService" android:exported="true">
            <intent-filter>
                <action android:name="com.example.vulnerableapp.SYNC"/>
            </intent-filter>
        </service>

        <receiver android:name=".SmsReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
            </intent-filter>
        </receiver>

        <provider
            android:name=".FileProvider"
            android:authorities="com.example.vulnerableapp.provider"
            android:exported="false"
            android:grantUriPermissions="true">
            <meta-data
                android:name="android.support.FILE_PROVIDER_PATHS"
                android:resource="@xml/file_paths"/>
        </provider>

        <provider
            android:name=".DataProvider"
            android:authorities="com.example.vulnerableapp.data"
            android:exported="true"/>

    </application>
</manifest>`;

// Analysis prompts removed as we are now using a local static parser.

// ── Components ──────────────────────────────────────────────────────────────

function MermaidGraph({ code }) {
  const ref = useRef(null);
  const mReady = useMermaid();
  const [svg, setSvg] = useState("");
  const [err, setErr] = useState("");

  useEffect(() => {
    if (!mReady || !code) return;
    setErr("");
    const id = "mermaid-" + Math.random().toString(36).substr(2, 9);
    window.mermaid.render(id, code)
      .then(({ svg }) => setSvg(svg))
      .catch(e => setErr("Graph Error: " + e.message));
  }, [mReady, code]);

  if (err) return (
    <div className="glass-card" style={{ padding: "1rem", color: "#f87171", fontFamily: "monospace", fontSize: 12, border: "1px solid #7f1d1d" }}>
      {err}<br/><span style={{color:"#64748b"}}>Raw Code:</span><br/><pre style={{marginTop:8,whiteSpace:"pre-wrap",color:"#94a3b8",fontSize:11}}>{code}</pre>
    </div>
  );
  if (!svg) return (
    <div style={{ display:"flex", alignItems:"center", gap:8, color:"#4ade80", fontFamily:"monospace", fontSize:13 }}>
      <span style={{animation:"spin 1s linear infinite", display:"inline-block"}}>⟳</span> Rendering graph...
    </div>
  );
  return <div ref={ref} dangerouslySetInnerHTML={{ __html: svg }} style={{ overflowX: "auto", maxWidth: "100%", padding: "1rem" }} />;
}

function ScoreGauge({ score, level }) {
  const clr = level === "CRITICAL" ? "#ef4444" : level === "HIGH" ? "#f97316" : level === "MEDIUM" ? "#fbbf24" : "#4ade80";
  const r = 54, circ = 2 * Math.PI * r;
  const dash = circ * (1 - score / 100);
  return (
    <div style={{ display:"flex", flexDirection:"column", alignItems:"center", gap:8 }}>
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r={r} fill="none" stroke="#1e293b" strokeWidth="12"/>
        <circle cx="70" cy="70" r={r} fill="none" stroke={clr} strokeWidth="12"
          strokeDasharray={circ} strokeDashoffset={dash}
          strokeLinecap="round" transform="rotate(-90 70 70)"
          style={{ transition: "stroke-dashoffset 1s cubic-bezier(.4,0,.2,1)" }}/>
        <text x="70" y="62" textAnchor="middle" fill={clr} fontSize="28" fontWeight="700" fontFamily="'Syne', sans-serif">{score}</text>
        <text x="70" y="82" textAnchor="middle" fill="#64748b" fontSize="11" fontFamily="monospace">/100</text>
        <text x="70" y="99" textAnchor="middle" fill={clr} fontSize="13" fontWeight="600" fontFamily="'Syne', sans-serif">{level}</text>
      </svg>
    </div>
  );
}

const TypeIcon = ({ type }) => {
  const icons = { Activity:"▣", Service:"⬡", BroadcastReceiver:"◉", ContentProvider:"⬢" };
  const colors = { Activity:"#60a5fa", Service:"#a78bfa", BroadcastReceiver:"#f472b6", ContentProvider:"#34d399" };
  return <span style={{ color: colors[type] || "#94a3b8", fontSize: 14, marginRight: 6 }}>{icons[type] || "◆"}</span>;
};

// ── Main App ────────────────────────────────────────────────────────────────

import { analyzeManifestLocally } from "./staticParser";

export default function App() {
  const [manifest, setManifest] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [tab, setTab] = useState("overview");
  const [expandedFinding, setExpandedFinding] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  
  const fileRef = useRef(null);

  const analyze = useCallback(async (xml) => {
    if (!xml.trim()) { setError("Paste or import an AndroidManifest.xml"); return; }
    
    setLoading(true); 
    setError(""); 
    setResult(null);
    
    // Simulate slight delay for premium feel
    setTimeout(() => {
      try {
        const parsedResults = analyzeManifestLocally(xml);
        setResult(parsedResults);
        setTab("overview");
      } catch (e) {
        setError("Analysis Error: " + e.message);
      } finally {
        setLoading(false);
      }
    }, 800);
  }, []);

  const handleFile = (file) => {
    const r = new FileReader();
    r.onload = (e) => { const txt = e.target.result; setManifest(txt); analyze(txt); };
    r.readAsText(file);
  };

  const handleDrop = (e) => {
    e.preventDefault(); setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  };

  const sev = result?.analysis_summary;
  const sevColor = sev ? (SEV[sev.risk_level]?.dot || "#94a3b8") : "#334155";

  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "components", label: `Components ${result ? `(${result.components?.length||0})` : ""}` },
    { id: "findings", label: `Findings ${result ? `(${result.findings?.length||0})` : ""}` },
    { id: "graph", label: "Surface Graph" },
    { id: "manifest", label: "Manifest" },
  ];

  return (
    <div style={{ minHeight: "100vh", paddingBottom: "4rem" }}>
      
      {/* Header */}
      <header style={{ background: "rgba(10, 22, 40, 0.7)", backdropFilter: "blur(12px)", borderBottom: "1px solid var(--glass-border)", padding: "1rem 2rem", position: "sticky", top: 0, zIndex: 50 }}>
        <div style={{ maxWidth: 1200, margin: "0 auto", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <div style={{ width: 40, height: 40, background: "linear-gradient(135deg, #0f3460, #1e4d8c)", borderRadius: 10, border: "1px solid var(--glass-border)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, boxShadow: "0 0 20px rgba(96, 165, 250, 0.2)" }}>⬡</div>
            <div>
              <h1 style={{ fontSize: 20, color: "var(--primary)", letterSpacing: "0.05em" }}>ATTACK SURFACE MAPPER</h1>
              <div style={{ fontSize: 10, color: "#475569", letterSpacing: "0.2em", fontFamily: "monospace" }}>SEC-AUDIT v1.0 • ANDROID</div>
            </div>
          </div>
          <div style={{ display: "flex", gap: "1rem" }}>
            {result && (
              <div style={{ display:"flex", alignItems:"center", gap: 8, background: "rgba(30, 41, 59, 0.5)", padding: "4px 12px", borderRadius: 20, border: "1px solid var(--glass-border)" }}>
                <div style={{ width: 8, height: 8, borderRadius: "50%", background: sevColor, boxShadow: `0 0 10px ${sevColor}` }}/>
                <span style={{ fontSize: 12, color: "#94a3b8", fontWeight: 500 }}>{result.app_package}</span>
              </div>
            )}
          </div>
        </div>
      </header>

      <main style={{ maxWidth: 1200, margin: "0 auto", padding: "2rem" }}>
        
        {/* Upload Zone */}
        {!result && !loading && (
          <div className="anim-fade-in">
            <div
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileRef.current?.click()}
              className="glass-card"
              style={{
                border: `2px dashed ${dragOver ? "var(--primary)" : "var(--glass-border)"}`,
                padding: "4rem 2rem", textAlign: "center",
                cursor: "pointer", transition: "all 0.3s ease",
                marginBottom: "2rem",
                position: "relative",
                overflow: "hidden"
              }}>
              {dragOver && <div className="scanline" />}
              <div style={{ fontSize: 50, marginBottom: 16, opacity: 0.8 }}>📁</div>
              <h2 style={{ fontSize: 24, marginBottom: 8, color: "var(--primary)" }}>Analyze Android Manifest</h2>
              <p style={{ color: "#94a3b8", marginBottom: "1rem" }}>Drop your <code style={{color: "var(--secondary)"}}>AndroidManifest.xml</code> here</p>
              <div style={{ fontSize: 12, color: "#475569", textTransform: "uppercase", letterSpacing: "0.1em" }}>or click to browse</div>
              <input ref={fileRef} type="file" accept=".xml" style={{display:"none"}} onChange={e => e.target.files[0] && handleFile(e.target.files[0])}/>
            </div>

            <div style={{ display:"grid", gridTemplateColumns: "1fr 200px", gap: 16 }}>
              <textarea
                placeholder="Paste XML content here..."
                value={manifest}
                onChange={e => setManifest(e.target.value)}
                style={{
                  minHeight: 200, background: "rgba(15, 23, 42, 0.4)", borderRadius: 16, border: "1px solid var(--glass-border)",
                  fontSize: 13, resize: "none"
                }}
              />
              <div style={{ display:"flex", flexDirection:"column", gap: 12 }}>
                <button onClick={() => analyze(manifest)} style={{
                  background: "linear-gradient(135deg, #059669, #10b981)", border: "none", color: "#020617",
                  height: "100%", fontSize: 16, fontWeight: 800, textTransform: "uppercase", letterSpacing: "0.05em"
                }}>Start Analysis</button>
                <button onClick={() => { setManifest(SAMPLE_MANIFEST); }} style={{
                  background: "rgba(30, 41, 59, 0.5)", border: "1px solid var(--glass-border)", color: "#94a3b8"
                }}>Demo Example</button>
              </div>
            </div>
            {error && <div className="glass-card" style={{ marginTop: 20, color: "#f87171", padding: "1rem", border: "1px solid #7f1d1d", background: "rgba(127, 29, 29, 0.1)" }}>{error}</div>}
          </div>
        )}

        {/* Loading State */}
        {loading && (
          <div style={{ display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", minHeight: "40vh", color: "var(--primary)" }}>
            <div style={{ position: "relative", width: 80, height: 80, marginBottom: 24 }}>
              <div style={{ position: "absolute", inset: 0, border: "4px solid var(--primary)", opacity: 0.1, borderRadius: "50%" }}/>
              <div style={{ position: "absolute", inset: 0, border: "4px solid transparent", borderTopColor: "var(--primary)", borderRadius: "50%", animation: "spin 1s linear infinite" }}/>
              <div style={{ position: "absolute", inset: 20, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 24 }}>⬡</div>
            </div>
            <h3 style={{ marginBottom: 12, letterSpacing: "0.1em" }}>Claude is auditing your manifest...</h3>
            <p style={{ color: "#475569", fontSize: 13 }}>Extracting components and identifying attack vectors</p>
          </div>
        )}

        {/* Results */}
        {result && !loading && (
          <div className="anim-fade-in">
            <div style={{ display:"flex", alignItems:"center", gap: 12, marginBottom: "2rem" }}>
              <button onClick={() => { setResult(null); setManifest(""); setTab("overview"); }} style={{
                background:"rgba(30, 41, 59, 0.3)", border:"1px solid var(--glass-border)", color:"#94a3b8", padding:"8px 16px"
              }}>← New Audit</button>
              <div className="glass-card" style={{ display:"flex", padding: 4, borderRadius: 12 }}>
                {tabs.map(t => (
                  <button key={t.id} onClick={() => setTab(t.id)} style={{
                    background: tab === t.id ? "rgba(96, 165, 250, 0.1)" : "transparent",
                    border: "none", color: tab === t.id ? "var(--secondary)" : "#475569",
                    padding:"8px 16px", borderRadius: 8, fontSize: 13, fontWeight: 600
                  }}>{t.label}</button>
                ))}
              </div>
            </div>

            {/* OVERVIEW */}
            {tab === "overview" && (
              <div className="anim-fade-in">
                <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit, minmax(200px, 1fr))", gap: 20, marginBottom: "2rem" }}>
                  <div className="glass-card" style={{ padding: "2rem", display:"flex", justifyContent:"center", gridRow: "span 2" }}>
                    <ScoreGauge score={sev.surface_risk_score} level={sev.risk_level}/>
                  </div>
                  {[
                    { label:"Total Components", val: sev.total_components, icon:"◆", color:"var(--secondary)" },
                    { label:"Exposed Components", val: sev.exported_components, icon:"⬡", color:"var(--warning)" },
                    { label:"Critical Findings", val: sev.critical_findings_count, icon:"⚠", color:"var(--danger)" },
                    { label:"Risk Level", val: sev.risk_level, icon:"⚡", color: sevColor },
                  ].map(m => (
                    <div key={m.label} className="glass-card" style={{ padding:"1.5rem" }}>
                      <div style={{ fontSize: 11, color:"#475569", letterSpacing:"0.1em", marginBottom:8, textTransform: "uppercase" }}>{m.label}</div>
                      <div style={{ fontSize: 32, fontWeight:800, color: m.color }}>{m.val}</div>
                    </div>
                  ))}
                </div>

                <div className="glass-card" style={{ padding: "1.5rem", marginBottom: "2rem" }}>
                  <h4 style={{ color: "var(--primary)", marginBottom: "1.5rem", fontSize: 14, letterSpacing: "0.1em" }}>PRIORITY FINDINGS</h4>
                  <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                    {result.findings?.filter(f => ["CRITICAL","HIGH"].includes(f.severity)).map(f => (
                      <div key={f.id} onClick={() => { setTab("findings"); setExpandedFinding(f.id); }}
                        className="glass-card"
                        style={{ display:"flex", alignItems:"center", gap:16, padding:"1rem", cursor:"pointer", border: `1px solid ${SEV[f.severity]?.border}40` }}>
                        <span style={{ width:10, height:10, borderRadius:"50%", background: SEV[f.severity]?.dot, boxShadow: `0 0 10px ${SEV[f.severity]?.dot}` }}/>
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: 14, fontWeight: 600, color: "#e2e8f0" }}>{f.title}</div>
                          <div style={{ fontSize: 11, color: "#475569", marginTop: 4 }}>{f.component}</div>
                        </div>
                        <span style={{ fontSize:10, fontWeight:700, padding:"4px 10px", borderRadius:8, background: SEV[f.severity]?.bg, color: SEV[f.severity]?.text }}>{f.severity}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="glass-card" style={{ padding: "1.5rem" }}>
                  <h4 style={{ color: "var(--primary)", marginBottom: "1.5rem", fontSize: 14, letterSpacing: "0.1em" }}>SECURITY RECOMMENDATIONS</h4>
                  <ul style={{ listStyle: "none", padding: 0 }}>
                    {result.global_recommendations?.map((r, i) => (
                      <li key={i} style={{ padding: "12px 0", borderBottom: "1px solid var(--glass-border)", color: "#94a3b8", fontSize: 14, display: "flex", gap: 12 }}>
                        <span style={{ color: "var(--primary)" }}>⚡</span> {r}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}

            {/* COMPONENTS */}
            {tab === "components" && (
              <div className="glass-card anim-fade-in" style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                  <thead>
                    <tr style={{ background: "rgba(15, 23, 42, 0.5)", textAlign: "left" }}>
                      <th style={{ padding: "1rem", color: "#475569" }}>NAME</th>
                      <th style={{ padding: "1rem", color: "#475569" }}>TYPE</th>
                      <th style={{ padding: "1rem", color: "#475569" }}>EXPORTED</th>
                      <th style={{ padding: "1rem", color: "#475569" }}>PERMISSION</th>
                      <th style={{ padding: "1rem", color: "#475569", textAlign: "center" }}>RISK</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.components?.map((c, i) => {
                      const risk = c.risk_score > 60 ? "CRITICAL" : c.risk_score > 40 ? "HIGH" : c.risk_score > 20 ? "MEDIUM" : "LOW";
                      return (
                        <tr key={i} style={{ borderBottom: "1px solid var(--glass-border)" }}>
                          <td style={{ padding: "1rem" }}>
                            <div style={{ color: "#e2e8f0", fontWeight: 500 }}>{c.name}</div>
                          </td>
                          <td style={{ padding: "1rem" }}><TypeIcon type={c.type}/> {c.type}</td>
                          <td style={{ padding: "1rem" }}>
                            <span style={{ color: c.exported ? "var(--danger)" : "var(--primary)", fontWeight: 600 }}>{c.exported ? "YES" : "NO"}</span>
                          </td>
                          <td style={{ padding: "1rem", color: c.permission ? "var(--primary)" : "#475569", fontFamily: "monospace", fontSize: 11 }}>{c.permission || "none"}</td>
                          <td style={{ padding: "1rem", textAlign: "center" }}>
                            <span style={{ color: SEV[risk]?.dot, fontWeight: 800 }}>{c.risk_score}</span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            {/* FINDINGS */}
            {tab === "findings" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 16 }} className="anim-fade-in">
                {result.findings?.sort((a,b) => {
                  const ord = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};
                  return (ord[a.severity]||9)-(ord[b.severity]||9);
                }).map(f => {
                  const open = expandedFinding === f.id;
                  const s = SEV[f.severity] || SEV.LOW;
                  return (
                    <div key={f.id} className="glass-card" style={{ border: `1px solid ${open ? s.border : "var(--glass-border)"}` }}>
                      <div onClick={() => setExpandedFinding(open ? null : f.id)} style={{ padding: "1.25rem", cursor: "pointer", display: "flex", alignItems: "center", gap: 16 }}>
                        <span style={{ width:12, height:12, borderRadius:"50%", background: s.dot, boxShadow: `0 0 10px ${s.dot}` }}/>
                        <span style={{ fontSize: 10, fontWeight: 800, padding: "4px 10px", borderRadius: 8, background: s.bg, color: s.text, textTransform: "uppercase" }}>{f.severity}</span>
                        <span style={{ flex: 1, fontWeight: 600, color: "#e2e8f0" }}>{f.title}</span>
                        <span style={{ color: "#475569" }}>{open ? "▲" : "▼"}</span>
                      </div>
                      {open && (
                        <div style={{ padding: "0 1.25rem 1.25rem", borderTop: "1px solid var(--glass-border)" }}>
                          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginTop: "1.25rem" }}>
                            <div>
                              <div style={{ fontSize: 10, color: "#475569", marginBottom: 8, fontWeight: 700 }}>WHY IT'S RISKY</div>
                              <p style={{ fontSize: 14, color: "#94a3b8", lineHeight: 1.6 }}>{f.why_risky}</p>
                            </div>
                            <div>
                              <div style={{ fontSize: 10, color: "var(--danger)", marginBottom: 8, fontWeight: 700 }}>ATTACK SCENARIO</div>
                              <p style={{ fontSize: 14, color: "#fca5a5", lineHeight: 1.6 }}>{f.attack_scenario}</p>
                            </div>
                          </div>
                          <div style={{ marginTop: "1.5rem", padding: "1.25rem", background: "rgba(16, 185, 129, 0.05)", borderRadius: 12, border: "1px solid rgba(16, 185, 129, 0.2)" }}>
                            <div style={{ fontSize: 10, color: "var(--primary)", marginBottom: 8, fontWeight: 700 }}>RECOMMENDED FIX</div>
                            <p style={{ fontSize: 14, color: "#a7f3d0", marginBottom: 12 }}>{f.fix}</p>
                            {f.fix_code_example && (
                              <pre style={{ background: "#020617", padding: "1rem", borderRadius: 8, fontSize: 12, color: "var(--primary)", overflowX: "auto" }}>{f.fix_code_example}</pre>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            {/* GRAPH */}
            {tab === "graph" && (
              <div className="glass-card anim-fade-in" style={{ padding: "1rem" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
                  <h4 style={{ color: "#475569", fontSize: 11, letterSpacing: "0.1em" }}>RELATIONSHIP GRAPH</h4>
                </div>
                <MermaidGraph code={result.mermaid_graph}/>
              </div>
            )}

            {/* MANIFEST */}
            {tab === "manifest" && (
              <div className="glass-card anim-fade-in" style={{ padding: "1.5rem" }}>
                <pre style={{ fontSize: 12, color: "#94a3b8", lineHeight: 1.6, overflowX: "auto" }}>{manifest}</pre>
              </div>
            )}
          </div>
        )}
      </main>

      <footer style={{ position: "fixed", bottom: 0, left: 0, right: 0, padding: "1rem", textAlign: "center", fontSize: 10, color: "#475569", borderTop: "1px solid var(--glass-border)", background: "rgba(2, 6, 23, 0.8)", backdropFilter: "blur(8px)" }}>
        PROJET-APPS-MOBILE • ANDROID SECURITY AUDIT TOOL • POWERED BY CLAUDE 3.5 SONNET
      </footer>
    </div>
  );
}
