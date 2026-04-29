/**
 * Android Manifest Static Parser - ENHANCED VERSION
 * Analyzes AndroidManifest.xml for security vulnerabilities locally.
 */

export const analyzeManifestLocally = (xmlContent) => {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlContent, "text/xml");
  
  const parseError = xmlDoc.getElementsByTagName("parsererror");
  if (parseError.length > 0) {
    throw new Error("Invalid XML format: " + parseError[0].textContent);
  }

  const manifest = xmlDoc.getElementsByTagName("manifest")[0];
  const application = xmlDoc.getElementsByTagName("application")[0];
  const appPackage = manifest?.getAttribute("package") || "unknown.package";
  
  const components = [];
  const findings = [];
  let totalRiskScore = 0;

  // --- 1. GLOBAL PERMISSIONS ANALYSIS ---
  const usesPermissions = xmlDoc.getElementsByTagName("uses-permission");
  const permissionsList = Array.from(usesPermissions).map(p => p.getAttribute("android:name"));
  
  const dangerousPermissions = [
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA"
  ];

  const foundDangerousPermissions = permissionsList.filter(p => dangerousPermissions.includes(p));
  if (foundDangerousPermissions.length > 0) {
    findings.push({
      id: "dangerous_permissions",
      severity: "MEDIUM",
      title: "Dangerous Permissions Requested",
      why_risky: `The app requests high-privilege permissions: ${foundDangerousPermissions.map(p => p.split('.').pop()).join(', ')}. These grant access to sensitive user data.`,
      attack_scenario: "A malicious actor exploiting the app could leverage these permissions to exfiltrate private data like contacts, location, or files.",
      fix: "Follow the Principle of Least Privilege. Only request permissions that are absolutely necessary.",
      priority: "SHORT_TERM"
    });
    totalRiskScore += 10;
  }

  const hasInternet = permissionsList.includes("android.permission.INTERNET");

  // --- 2. GLOBAL APPLICATION CHECKS ---
  const allowBackup = application?.getAttribute("android:allowBackup") !== "false";
  const debuggable = application?.getAttribute("android:debuggable") === "true";
  const usesCleartextTraffic = application?.getAttribute("android:usesCleartextTraffic") === "true";
  const requestLegacyExternalStorage = application?.getAttribute("android:requestLegacyExternalStorage") === "true";

  if (allowBackup) {
    findings.push({
      id: "app_backup",
      severity: "HIGH",
      title: "Backup Enabled (Data Extraction Risk)",
      why_risky: "android:allowBackup is enabled. This allows the entire app's private data to be extracted via 'adb backup' without root access.",
      attack_scenario: "An attacker with physical access or ADB access to the device can steal user databases, shared preferences, and private files.",
      fix: "Set android:allowBackup=\"false\" in the <application> tag.",
      priority: "IMMEDIATE"
    });
    totalRiskScore += 15;
  }

  if (debuggable) {
    findings.push({
      id: "app_debug",
      severity: "CRITICAL",
      title: "Application is Debuggable",
      why_risky: "The app is marked as debuggable. Attackers can attach a debugger, dump memory, and execute arbitrary code in the app's context.",
      attack_scenario: "A malicious app on the same device could use JDWP to take control of this app or bypass authentication logic.",
      fix: "Remove android:debuggable=\"true\" or set it to \"false\" for production builds.",
      priority: "IMMEDIATE"
    });
    totalRiskScore += 15;
  }

  if (usesCleartextTraffic) {
    findings.push({
      id: "cleartext_traffic",
      severity: "HIGH",
      title: "Cleartext Traffic Allowed",
      why_risky: "The app allows non-HTTPS traffic. Data transmitted over the network is unencrypted and vulnerable to interception.",
      attack_scenario: "An attacker on the same Wi-Fi network can perform a Man-in-the-Middle (MITM) attack to steal credentials or session tokens.",
      fix: "Set android:usesCleartextTraffic=\"false\" and use a Network Security Configuration to enforce HTTPS.",
      priority: "IMMEDIATE"
    });
    totalRiskScore += 15;
  }

  if (requestLegacyExternalStorage) {
    findings.push({
      id: "legacy_storage",
      severity: "MEDIUM",
      title: "Legacy External Storage Enabled",
      why_risky: "The app requests a bypass for Scoped Storage, which was introduced to improve user privacy by restricting file access.",
      attack_scenario: "The app maintains broad access to the device's shared storage, increasing the risk of data leakage or tampering.",
      fix: "Migrate to Scoped Storage and remove android:requestLegacyExternalStorage=\"true\".",
      priority: "SHORT_TERM"
    });
    totalRiskScore += 10;
  }

  // --- 3. RISK CORRELATION LOGIC ---
  if (debuggable && allowBackup) {
    findings.push({
      id: "corr_debug_backup",
      severity: "CRITICAL",
      title: "COMBINED RISK: Debuggable + Backup",
      why_risky: "Having both debuggable and backup enabled is a devastating combination for data protection.",
      attack_scenario: "Attackers can extract the backup AND use debug tools to decrypt any local secrets found in that backup.",
      fix: "Disable both backup and debuggable attributes.",
      priority: "IMMEDIATE"
    });
    totalRiskScore += 10; // Extra penalty
  }

  if (usesCleartextTraffic && hasInternet) {
    findings.push({
      id: "corr_cleartext_internet",
      severity: "HIGH",
      title: "COMBINED RISK: Cleartext + Internet",
      why_risky: "App has internet access and explicitly allows unencrypted traffic.",
      attack_scenario: "All outbound API calls are likely happening over HTTP, exposing all user data to sniffing.",
      fix: "Disable cleartext traffic and enforce TLS.",
      priority: "IMMEDIATE"
    });
  }

  // --- 4. COMPONENT ANALYSIS ---
  const types = ["activity", "service", "receiver", "provider"];
  const typeMap = {
    activity: "Activity",
    service: "Service",
    receiver: "BroadcastReceiver",
    provider: "ContentProvider"
  };

  types.forEach(type => {
    const elements = xmlDoc.getElementsByTagName(type);
    for (let i = 0; i < elements.length; i++) {
      const el = elements[i];
      const name = el.getAttribute("android:name") || "Unnamed";
      const intentFilters = el.getElementsByTagName("intent-filter");
      const hasIntentFilters = intentFilters.length > 0;
      
      let exportedAttr = el.getAttribute("android:exported");
      let exported = exportedAttr === "true" || (exportedAttr === null && hasIntentFilters);
      const permission = el.getAttribute("android:permission");
      
      let riskScore = 0;
      let riskFlags = [];

      // Logic for exported components
      if (exported) {
        if (!permission) {
          riskScore += 30;
          riskFlags.push("Exported & Unprotected");
          findings.push({
            id: `exported_${name}`,
            severity: "HIGH",
            component: name,
            title: `${typeMap[type]} Exposed`,
            why_risky: "This component is accessible by any other app on the device without any security restriction.",
            attack_scenario: "A malicious app can send malicious intents to this component to perform actions on behalf of the user.",
            fix: `Add android:permission or set android:exported="false"`,
            priority: "IMMEDIATE"
          });
        } else {
          riskScore += 5;
          riskFlags.push("Exported (Protected)");
        }
      }

      // Provider specific risks
      if (type === "provider") {
        const grantUriPerms = el.getAttribute("android:grantUriPermissions") === "true";
        if (exported && grantUriPerms) {
          riskScore += 40;
          riskFlags.push("CRITICAL: GrantUriPermissions enabled on Exported Provider");
          findings.push({
            id: `provider_grant_${name}`,
            severity: "CRITICAL",
            component: name,
            title: "Critical Content Provider Vulnerability",
            why_risky: "The provider is exported AND allows URI permission granting. This is a common pattern for path traversal and unauthorized data access.",
            attack_scenario: "An attacker can trick the app into granting access to its private files by exploiting the broad URI permission system.",
            fix: "Disable exported if possible, or use granular path-based permissions.",
            priority: "IMMEDIATE"
          });
          totalRiskScore += 20;
        }
      }

      // Deep link risks
      if (type === "activity") {
        for (let j = 0; j < intentFilters.length; j++) {
          const dataTags = intentFilters[j].getElementsByTagName("data");
          for (let k = 0; k < dataTags.length; k++) {
            const scheme = dataTags[k].getAttribute("android:scheme");
            if (scheme === "http") {
              riskScore += 15;
              riskFlags.push("Insecure HTTP Deep Link");
              findings.push({
                id: `http_deeplink_${name}`,
                severity: "MEDIUM",
                component: name,
                title: "Insecure HTTP Deep Link",
                why_risky: "Activity handles unencrypted HTTP deep links.",
                attack_scenario: "Attacker can hijack the intent by registering a similar scheme or using MITM to trigger specific app behaviors.",
                fix: "Use 'https' only or App Links for stronger verification.",
                priority: "SHORT_TERM"
              });
            }
          }
        }
      }

      components.push({
        name,
        type: typeMap[type],
        exported,
        permission,
        intent_filters: Array.from(intentFilters).map(f => ({
          action: f.getElementsByTagName("action")[0]?.getAttribute("android:name"),
          category: f.getElementsByTagName("category")[0]?.getAttribute("android:name"),
          data_scheme: f.getElementsByTagName("data")[0]?.getAttribute("android:scheme")
        })),
        risk_score: Math.min(riskScore, 100),
        risk_flags: riskFlags
      });
      
      totalRiskScore += Math.floor(riskScore / 4);
    }
  });

  // Final Summary Logic
  const exportedCount = components.filter(c => c.exported).length;
  const surfaceScore = Math.min(totalRiskScore, 100);
  
  let riskLevel = "LOW";
  if (surfaceScore > 70 || findings.some(f => f.severity === "CRITICAL")) riskLevel = "CRITICAL";
  else if (surfaceScore > 45) riskLevel = "HIGH";
  else if (surfaceScore > 20) riskLevel = "MEDIUM";

  // --- 5. MERMAID GRAPH GENERATION ---
  let mermaid = "graph LR\n";
  mermaid += "  classDef danger fill:#450a0a,stroke:#dc2626,color:#fca5a5\n";
  mermaid += "  classDef warn fill:#431407,stroke:#ea580c,color:#fdba74\n";
  mermaid += "  classDef safe fill:#052e16,stroke:#16a34a,color:#86efac\n";

  components.forEach((c, idx) => {
    const shortName = c.name.split('.').pop();
    const nodeId = `C${idx}`;
    const style = c.exported ? (c.permission ? "warn" : "danger") : "safe";
    
    mermaid += `  ${nodeId}["${c.type}: ${shortName}"]:::${style}\n`;
    
    c.intent_filters.forEach((f, fIdx) => {
      if (f.action) {
        const actionId = `A${idx}_${fIdx}`;
        mermaid += `  ${actionId}((Intent: ${f.action.split('.').pop()}))\n`;
        mermaid += `  ${actionId} --> ${nodeId}\n`;
      }
    });
  });

  return {
    app_package: appPackage,
    analysis_summary: {
      total_components: components.length,
      exported_components: exportedCount,
      surface_risk_score: surfaceScore,
      risk_level: riskLevel,
      critical_findings_count: findings.filter(f => f.severity === "CRITICAL").length
    },
    components,
    findings,
    mermaid_graph: mermaid,
    global_recommendations: [
      "CRITICAL: Fix all GrantUriPermissions issues in Content Providers immediately.",
      "Disable android:allowBackup and android:debuggable for production releases.",
      "Enforce HTTPS by setting usesCleartextTraffic=\"false\" and migrating deep links to HTTPS.",
      "Minimize the use of dangerous permissions and implement Scoped Storage.",
      "Ensure all exported components are protected by signature-level permissions if they are for internal use."
    ]
  };
};
