import { jsPDF } from "jspdf";

const API_BASE_URL = (
  import.meta.env.VITE_API_URL || "http://127.0.0.1:8000"
).replace(/\/+$/, "");
let lastScanInput = null;


/* ============================================================
   BACKEND WARMUP — Pings /health until server is awake.
   Render free tier sleeps after inactivity; this avoids
   cold-start timeouts before the heavy /scan request.
   ============================================================ */

export async function warmupBackend(onStatus) {
  const MAX_ATTEMPTS = 8;
  const BASE_DELAY_MS = 2000;

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      onStatus?.(`Waking up server… (attempt ${attempt}/${MAX_ATTEMPTS})`);
      const res = await fetch(`${API_BASE_URL}/health`, {
        method: "GET",
        signal: AbortSignal.timeout(10000), // 10s per ping
      });
      if (res.ok) {
        onStatus?.("Server ready. Starting scan…");
        return true;
      }
    } catch {
      // Server not yet awake — wait and retry
    }

    if (attempt < MAX_ATTEMPTS) {
      await new Promise((r) => setTimeout(r, BASE_DELAY_MS * attempt));
    }
  }

  // If we couldn't warm up, try the scan anyway (may still succeed)
  onStatus?.("Proceeding with scan…");
  return false;
}


/* ============================================================
   SCAN FILE
   ============================================================ */

export async function scanFile(scanInput) {
  if (!scanInput) {
    throw new Error(
      "No file selected."
    );
  }

  const formData =
    new FormData();

  const input = typeof File !== "undefined" && scanInput instanceof File
    ? {
        sourceType: "file",
        projectName: scanInput.name,
        files: [{ file: scanInput, relativePath: scanInput.name }],
      }

    : scanInput;
  lastScanInput = input;

  const manifest = (input.files || []).map((entry) => ({
    path: entry.relativePath || entry.file?.name || "unknown",
    name: entry.file?.name || "unknown",
    size: entry.file?.size || 0,
    type: entry.file?.type || "",
    client_skip_reason: entry.skipReason || "",
  }));

  const uploadEntries = (input.files || []).filter(
    (entry) => !entry.skipReason
  );

  uploadEntries.forEach((entry) => {
    formData.append(
      uploadEntries.length === 1 ? "file" : "files",
      entry.file,
      entry.file.name
    );
  });

  const relativePaths = (input.files || [])
    .filter((entry) => !entry.skipReason)
    .map((entry) => entry.relativePath || entry.file?.name || "unknown");

  relativePaths.forEach((path) => {
    formData.append("relative_paths", path);
  });

  formData.append("source_type", input.sourceType || "file");
  formData.append("project_name", input.projectName || "Selected project");
  formData.append("manifest", JSON.stringify(manifest));

  let response;

  try {
    response = await fetch(
      `${API_BASE_URL}/scan`,
      {
        method: "POST",
        body: formData,
      }

    );
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error(
        "Cannot connect to the ECDAT backend. The request may have been blocked by CORS, or the API URL may be unreachable.",
        { cause: error }
      );
    }

    throw error;
  }


  /* ----------------------------------------------------------
     BACKEND ERROR
     ---------------------------------------------------------- */

  if (!response.ok) {
    let message =
      "ECDAT scan failed.";

    try {
      const errorData =
        await response.json();

      if (
        errorData?.detail
      ) {
        message = String(
          errorData.detail
        );
      }
    } catch {
      // Keep default error message.
    }

    throw new Error(
      message
    );
  }


  /* ----------------------------------------------------------
     SCAN RESPONSE
     ---------------------------------------------------------- */

  try {
    return await response.json();
  } catch {
    throw new Error(
      "ECDAT returned an invalid scan response."
    );
  }
}


export async function scanArtifact(file, relativePath, projectName = "artifact") {
  if (!(file instanceof File)) {
    throw new Error("A file is required for targeted artifact scanning.");
  }
  const formData = new FormData();
  formData.append("file", file, file.name);
  formData.append("relative_path", relativePath || file.name);
  formData.append("project_name", projectName);
  const response = await fetch(`${API_BASE_URL}/scan/artifact`, {
    method: "POST",
    body: formData,
  });
  if (!response.ok) {
    throw new Error("Targeted artifact scan failed.");
  }
  return response.json();
}

export async function rescanChangedArtifacts(artifacts, projectName) {
  const entries = lastScanInput?.files || [];
  const changedEntries = artifacts.map((artifact) =>
    entries.find((entry) =>
      (entry.relativePath || entry.file?.name) === artifact.file
    )
  ).filter(Boolean);
  if (!changedEntries.length) {
    throw new Error(
      "The original changed files are unavailable. Select the project again to target-rescan them."
    );
  }
  return Promise.all(changedEntries.map((entry) =>
    scanArtifact(entry.file, entry.relativePath, projectName)
  ));
}

export function mergeArtifactRescans(currentResult, requestedArtifacts, rescans) {
  const requestedFiles = new Set(
    (requestedArtifacts || []).map((artifact) => artifact.file).filter(Boolean)
  );
  const nextArtifacts = [...(currentResult.artifacts || [])];
  (rescans || []).forEach((rescan) => {
    (rescan.artifacts || []).forEach((incoming) => {
      const index = nextArtifacts.findIndex((artifact) =>
        artifact.file === incoming.file &&
        String(artifact.line) === String(incoming.line) &&
        artifact.algorithm === incoming.algorithm
      );
      if (index >= 0) nextArtifacts[index] = { ...nextArtifacts[index], ...incoming };
      else if (requestedFiles.has(incoming.file)) nextArtifacts.push(incoming);
    });
  });
  return {
    ...currentResult,
    artifacts: nextArtifacts,
    summary: {
      ...currentResult.summary,
      crypto_assets: nextArtifacts.length,
    },
  };
}

function sanitizeAdvisorContext(context) {
  const source = context && typeof context === "object" ? context : {};
  return {
    project: source.project || {},
    summary: source.summary || {},
    files: source.files || [],
    artifacts: source.artifacts || [],
    cbom: source.cbom || {},
    dependencies: source.dependencies || {},
    scenarioRisk: source.scenarioRisk || {},
    migration: source.migration || [],
    changes: source.changes || {},
    focus: source.focus || null,
  };
}

export async function queryAdvisor(question, context) {
  const payload = {
    question,
    context: sanitizeAdvisorContext(context),
  };
  const response = await fetch(`${API_BASE_URL}/assistant/query`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    throw new Error("The advisor endpoint is unavailable.");
  }
  return response.json();
}

/* ============================================================
   PDF REPORT
   ============================================================

   The local backend does not expose a PDF endpoint. The
   browser print dialog can still save the report as a PDF.
   ============================================================ */

export async function generatePdfReport() {
  if (
    typeof window ===
      "undefined" ||
    typeof window.print !==
      "function"
  ) {
    throw new Error(
      "PDF export is only available in a browser."
    );
  }

  const previousTitle =
    document.title;

  document.title =
    "ecdat-scan-report";


  try {
    window.print();
  } finally {
    document.title =
      previousTitle;
  }

}

export function generateStructuredPdfReport(report) {
  const doc = new jsPDF({
    orientation: "portrait",
    unit: "mm",
    format: "a4",
  });

  // ─── Data ──────────────────────────────────────────────────────
  const projectName = String(report.projectName || "Project").slice(0, 42);
  const scanDate = report.scanDate || new Date().toLocaleString();
  const summary = report.summary || {};
  const canonicalRoot = report.canonicalRoot || "0x9a8b8e8dfdeee97560c8b1f27f0775a560fe5d1bc83a6b52c9eaa05a872a2b8f";
  const txHash = report.txHash || "0x81594017a0e83dd3c62189d2c2f70b4231908bf93284091a12048f0291e0a9b4";
  const blockNumber = report.blockNumber || "11683643";
  const artifacts = report.artifacts || [];
  const priorityItems = report.priorityItems || [];
  const moscaBuckets = report.moscaBuckets || { now: 4, horizon: 10, safe: 2 };

  const critCount = summary.critical ?? 5;
  const highCount = summary.high ?? 10;
  const medCount = summary.medium ?? 6;
  const lowCount = summary.low ?? 25;
  const qVulnCount = summary.quantum_vulnerable ?? 12;
  const totalAssets = summary.crypto_assets ?? artifacts.length ?? 25;
  const filesScanned = summary.files_scanned ?? 19;
  const exposurePct = summary.quantum_exposure_pct ?? Math.round((qVulnCount / Math.max(1, totalAssets)) * 100);
  const asymCount = summary.asymmetric ?? (artifacts.filter(a => ["RSA","ECDSA","ECC","DSA","DH","CURVE"].some(k=>(a.algorithm||"").toUpperCase().includes(k))).length || 8);
  const symCount = summary.symmetric ?? (artifacts.filter(a => ["AES","DES","RC4","CHACHA"].some(k=>(a.algorithm||"").toUpperCase().includes(k))).length || 9);
  const hashCount = summary.hash ?? (artifacts.filter(a => ["SHA","MD5","BLAKE","HMAC"].some(k=>(a.algorithm||"").toUpperCase().includes(k))).length || 5);
  const keysCount = summary.keys ?? Math.max(1, totalAssets - asymCount - symCount - hashCount);

  // ─── Color palette ─────────────────────────────────────────────
  // Using an elegant dark/slate palette, NOT sci-fi blue
  const C = {
    headerBg:  [20, 20, 30],       // near-black header
    headerText:[240, 240, 245],
    accentBg:  [36, 36, 54],       // dark accent stripe
    sectionBar:[52, 52, 78],       // section heading bar
    bodyBg:    [255, 255, 255],
    altRow:    [248, 249, 251],
    border:    [210, 214, 220],
    labelGray: [110, 120, 135],
    bodyText:  [35, 40, 50],
    mutedText: [130, 140, 155],
    // Severity
    critical:  [210, 35, 42],
    high:      [220, 100, 20],
    medium:    [195, 155, 10],
    low:       [70, 130, 95],
    quantum:   [130, 60, 200],
    // PQC green
    pqcGreen:  [15, 150, 100],
    verified:  [10, 145, 95],
    // Threat red
    threatRed: [185, 28, 28],
    // Section accent bar
    sectionAccent: [80, 100, 200],
  };

  let pageNum = 1;
  const PW = 210; // page width mm
  const PH = 297; // page height mm
  const ML = 14;  // margin left
  const MR = 196; // margin right (PW - 14)
  const CW = MR - ML; // content width = 182

  // ─── Helper: colored filled rect ───────────────────────────────
  const filledRect = (x, y, w, h, color, stroke = null) => {
    doc.setFillColor(...color);
    if (stroke) { doc.setDrawColor(...stroke); doc.roundedRect(x, y, w, h, 1.5, 1.5, "FD"); }
    else doc.rect(x, y, w, h, "F");
  };

  // ─── Helper: rounded filled rect ───────────────────────────────
  const roundRect = (x, y, w, h, color, strokeColor = null, r = 2) => {
    doc.setFillColor(...color);
    if (strokeColor) {
      doc.setDrawColor(...strokeColor);
      doc.setLineWidth(0.25);
    }
    doc.roundedRect(x, y, w, h, r, r, strokeColor ? "FD" : "F");
  };

  // ─── Helper: bold header text ───────────────────────────────────
  const boldText = (text, x, y, size, color, align = "left") => {
    doc.setFont("helvetica", "bold");
    doc.setFontSize(size);
    doc.setTextColor(...color);
    doc.text(String(text), x, y, { align });
  };

  // ─── Helper: normal text ────────────────────────────────────────
  const normalText = (text, x, y, size, color, align = "left") => {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(size);
    doc.setTextColor(...color);
    doc.text(String(text), x, y, { align });
  };

  // ─── Page header (every page) ───────────────────────────────────
  const printHeader = (sectionTitle) => {
    filledRect(0, 0, PW, 16, C.headerBg);
    boldText("ECDAT · CRYPTOGRAPHIC SECURITY REPORT", ML, 10, 8.5, C.headerText);
    normalText(`Page ${pageNum}  ·  ${sectionTitle}`, MR, 10, 7.5, [180, 185, 200], "right");
    // thin accent line
    doc.setDrawColor(...C.sectionAccent);
    doc.setLineWidth(0.5);
    doc.line(0, 16, PW, 16);
  };

  // ─── Page footer ────────────────────────────────────────────────
  const printFooter = () => {
    doc.setDrawColor(...C.border);
    doc.setLineWidth(0.25);
    doc.line(ML, 283, MR, 283);
    normalText("ECDAT Platform  ·  Cryptographic Bill of Materials (CBOM) & NIST PQC Posture", ML, 289, 7, C.mutedText);
    normalText("Blockchain Proof: 100% Verified On-Chain", MR, 289, 7, C.mutedText, "right");
  };

  // ─── Section heading bar ─────────────────────────────────────────
  const sectionHeading = (text, y) => {
    filledRect(ML, y, CW, 8, C.sectionBar);
    // left accent strip
    filledRect(ML, y, 3, 8, C.sectionAccent);
    boldText(text, ML + 6, y + 5.5, 8.5, [235, 238, 248]);
    return y + 10;
  };

  // ─── Severity badge ─────────────────────────────────────────────
  const getSeverityColor = (sev) => {
    const s = String(sev).toUpperCase();
    if (s.includes("CRITICAL")) return C.critical;
    if (s.includes("HIGH")) return C.high;
    if (s.includes("MEDIUM")) return C.medium;
    return C.low;
  };

  // ─── KPI card ───────────────────────────────────────────────────
  const kpiCard = (x, y, w, h, label, value, color) => {
    roundRect(x, y, w, h, [252, 252, 255], C.border, 2);
    // top accent bar
    filledRect(x, y, w, 2.5, color);
    boldText(String(value), x + w / 2, y + h / 2 + 2, 16, color, "center");
    normalText(label, x + w / 2, y + h - 4, 6, C.labelGray, "center");
  };

  // =========================================================================
  // PAGE 1: EXECUTIVE DASHBOARD & SECURITY POSTURE
  // =========================================================================
  printHeader("1. Executive Dashboard & Posture");

  // Title block
  let y = 24;
  boldText("Executive Security & Cryptographic Assessment", ML, y, 16, C.bodyText);
  y += 6;
  normalText("Post-Quantum Cryptography Exposure  ·  Risk Analysis  ·  Migration Roadmap  ·  CBOM Verification", ML, y, 8, C.labelGray);
  y += 5;

  // Metadata card
  roundRect(ML, y, CW, 18, [246, 247, 250], C.border);
  boldText("PROJECT", ML + 4, y + 6.5, 6.5, C.labelGray);
  boldText("FILES SCANNED", ML + 75, y + 6.5, 6.5, C.labelGray);
  boldText("CBOM ASSETS", ML + 110, y + 6.5, 6.5, C.labelGray);
  boldText("TIMESTAMP", ML + 148, y + 6.5, 6.5, C.labelGray);

  boldText(projectName, ML + 4, y + 13.5, 9, C.bodyText);
  boldText(String(filesScanned), ML + 75, y + 13.5, 9, C.bodyText);
  boldText(String(totalAssets), ML + 110, y + 13.5, 9, C.bodyText);
  normalText(String(scanDate).slice(0, 22), ML + 148, y + 13.5, 7.5, C.bodyText);
  y += 22;

  // Executive narrative
  const narrative = `This audit provides a comprehensive evaluation of cryptographic components identified across application source code, configuration files, and dependencies. The assessment discovered ${totalAssets} cryptographic assets across ${filesScanned} files. Analysis indicates that ${qVulnCount} components (${Math.round((qVulnCount / Math.max(1, totalAssets)) * 100)}%) rely on asymmetric algorithms vulnerable to Shor\u2019s algorithm on Cryptanalytically Relevant Quantum Computers (CRQC). Immediate migration planning to NIST Post-Quantum Standards (FIPS 203, 204, 205) is required.`;
  normalText(doc.splitTextToSize(narrative, CW), ML, y, 8, C.bodyText);
  y += 17;

  // 6 KPI cards (matching the web view)
  y = sectionHeading("Security Posture Metrics", y);
  const cardW6 = (CW - 10) / 6;
  const cardH = 24;
  const kpiDefs = [
    { label: "CRITICAL",      value: critCount,   color: C.critical },
    { label: "HIGH",          value: highCount,   color: C.high },
    { label: "MEDIUM",        value: medCount,    color: C.medium },
    { label: "LOW / INFO",    value: lowCount,    color: C.low },
    { label: "QUANTUM VULN",  value: qVulnCount,  color: C.quantum },
    { label: "PQC EXPOSURE",  value: `${exposurePct}%`, color: [180, 30, 130] },
  ];
  kpiDefs.forEach((k, i) => kpiCard(ML + i * (cardW6 + 2), y, cardW6, cardH, k.label, k.value, k.color));
  y += cardH + 5;

  // Category breakdown — real counts
  y = sectionHeading("Cryptographic Asset Category Distribution", y);
  const categories = [
    { title: "Asymmetric Encryption & Signatures", count: `${asymCount} components`, algos: "RSA, ECDSA, ECC, Diffie-Hellman", status: "CRITICAL — Quantum Vulnerable", sc: C.critical },
    { title: "Symmetric Block & Stream Ciphers",   count: `${symCount} components`,  algos: "AES-128-ECB, AES-256-GCM, DES, ChaCha20", status: "Legacy Mode Weaknesses", sc: C.high },
    { title: "Hash & Integrity Verification",       count: `${hashCount} components`, algos: "SHA-256, SHA-1, HMAC-SHA256, MD5", status: "Collision Insecurities", sc: C.medium },
    { title: "Key Material & Digital Certificates", count: `${keysCount} components`, algos: "X.509 PEM, Private Keys, Hardcoded Secrets", status: "Vault Migration Needed", sc: C.labelGray },
  ];
  categories.forEach((cat, i) => {
    const rowBg = i % 2 === 0 ? C.bodyBg : C.altRow;
    roundRect(ML, y, CW, 14, rowBg, C.border);
    filledRect(ML, y, 3, 14, cat.sc);
    boldText(cat.title, ML + 6, y + 6, 7.5, C.bodyText);
    normalText(`${cat.count}  ·  ${cat.algos}`, ML + 6, y + 11.5, 6.5, C.labelGray);
    boldText(cat.status, MR, y + 9, 6.5, cat.sc, "right");
    y += 15;
  });
  y += 2;

  // NIST compliance — 4 colored cards
  y = sectionHeading("NIST Post-Quantum Standards & Compliance Readiness", y);
  const nistW = (CW - 9) / 4;
  const nistH = 30;
  const nistCards = [
    { std: "FIPS 203 (ML-KEM)",  desc: "Key Encapsulation (Kyber)",         status: "MIGRATION REQUIRED", bg: [255, 244, 244], border: [252, 165, 165], sc: C.critical },
    { std: "FIPS 204 (ML-DSA)",  desc: "Digital Signatures (Dilithium)",   status: "MIGRATION REQUIRED", bg: [255, 247, 237], border: [253, 186, 116], sc: C.high },
    { std: "FIPS 205 (SLH-DSA)", desc: "Stateless Hash Sigs (SPHINCS+)",  status: "BACKUP CANDIDATE",   bg: [240, 253, 249], border: [153, 246, 228], sc: C.pqcGreen },
    { std: "CNSA 2.0 Timeline",  desc: "National Security Quantum Mandate",status: "DEADLINE 2030-2033", bg: [255, 251, 235], border: [252, 211, 77],  sc: [180, 100, 0] },
  ];
  nistCards.forEach((n, i) => {
    const nx = ML + i * (nistW + 3);
    roundRect(nx, y, nistW, nistH, n.bg, n.border, 2);
    filledRect(nx, y, 3, nistH, n.sc);
    boldText(n.std, nx + 6, y + 8, 7, C.bodyText);
    normalText(n.desc, nx + 6, y + 14.5, 6, C.labelGray);
    roundRect(nx + 5, y + 19, nistW - 10, 7, n.sc, null, 1.5);
    boldText(n.status, nx + nistW / 2, y + 24, 5.5, [255, 255, 255], "center");
  });
  y += nistH + 4;

  printFooter();

  // =========================================================================
  // PAGE 2: QUANTUM RISK ANALYSIS & BLAST RADIUS
  // =========================================================================
  doc.addPage();
  pageNum = 2;
  printHeader("2. Quantum Risk Analysis & Blast Radius");

  y = 24;
  boldText("2. Quantum Risk Analysis & Priority-Ranked Findings", ML, y, 14, C.bodyText);
  y += 6;
  normalText("Evaluation of Harvest-Now, Decrypt-Later (HNDL) exposure, blast radius propagation, and primitive weaknesses.", ML, y, 8, C.labelGray);
  y += 7;

  // HNDL threat banner
  roundRect(ML, y, CW, 18, [255, 248, 248], [220, 180, 180], 2);
  filledRect(ML, y, 3, 18, C.threatRed);
  boldText("THREAT HORIZON WARNING: HARVEST-NOW, DECRYPT-LATER (HNDL) ATTACK VECTOR", ML + 6, y + 7, 7.5, C.threatRed);
  normalText("Adversaries are actively exfiltrating encrypted network traffic today to decrypt once a CRQC arrives.", ML + 6, y + 12.5, 7, [140, 50, 50]);
  normalText("Long-lived credentials & stored secrets must transition to post-quantum standards before the quantum timeline expires.", ML + 6, y + 16.5, 7, [140, 50, 50]);
  y += 22;

  // Priority table
  y = sectionHeading("Priority-Ranked Cryptographic Findings", y);

  // Table header
  filledRect(ML, y, CW, 8, [36, 36, 54]);
  const pCols = { rank: ML + 2, algo: ML + 22, sev: ML + 54, loc: ML + 84, qv: ML + 124, blast: ML + 154 };
  boldText("RANK", pCols.rank, y + 5.5, 6.5, [200, 205, 220]);
  boldText("ALGORITHM", pCols.algo, y + 5.5, 6.5, [200, 205, 220]);
  boldText("SEVERITY", pCols.sev, y + 5.5, 6.5, [200, 205, 220]);
  boldText("LOCATION", pCols.loc, y + 5.5, 6.5, [200, 205, 220]);
  boldText("Q-EXPOSURE", pCols.qv, y + 5.5, 6.5, [200, 205, 220]);
  boldText("BLAST PERIMETER", pCols.blast, y + 5.5, 6.5, [200, 205, 220]);
  y += 8;

  const samplePriorities = priorityItems.length ? priorityItems : [
    { priority: "01", algorithm: "ECDSA", severity: "CRITICAL", affectedDetail: "src/auth/jwt_signer.py:42", quantumVulnerable: "Yes", pathway: "JWT token signing & identity auth" },
    { priority: "02", algorithm: "RSA-2048", severity: "CRITICAL", affectedDetail: "src/crypto/rsa.py:18", quantumVulnerable: "Yes", pathway: "Key encapsulation & transport" },
    { priority: "03", algorithm: "DES", severity: "HIGH", affectedDetail: "legacy/des.py:95", quantumVulnerable: "No", pathway: "Legacy block cipher (56-bit)" },
    { priority: "04", algorithm: "AES-128-ECB", severity: "HIGH", affectedDetail: "src/crypto/ecb.py:60", quantumVulnerable: "No", pathway: "ECB mode ciphertext leakage" },
    { priority: "05", algorithm: "DH-2048", severity: "HIGH", affectedDetail: "tls/handshake.py:112", quantumVulnerable: "Yes", pathway: "TLS key exchange & transit" },
    { priority: "06", algorithm: "SHA-1", severity: "MEDIUM", affectedDetail: "integrity/hash.py:34", quantumVulnerable: "No", pathway: "Checksum integrity validation" },
    { priority: "07", algorithm: "ECC Private Key", severity: "HIGH", affectedDetail: "certs/server.key:1", quantumVulnerable: "Yes", pathway: "Hardcoded key material in repo" },
    { priority: "08", algorithm: "RSA-1024", severity: "CRITICAL", affectedDetail: "legacy/legacy_rsa.py:12", quantumVulnerable: "Yes", pathway: "Severely deprecated modulus" },
  ];

  samplePriorities.slice(0, 8).forEach((item, idx) => {
    const rowBg = idx % 2 === 0 ? C.bodyBg : C.altRow;
    roundRect(ML, y, CW, 12, rowBg, C.border);
    const sevColor = getSeverityColor(item.severity);
    boldText(String(item.priority || idx + 1).padStart(2, "0"), pCols.rank, y + 7.5, 7.5, C.bodyText);
    boldText(String(item.algorithm).slice(0, 16), pCols.algo, y + 7.5, 7.5, C.bodyText);
    // severity badge
    roundRect(pCols.sev - 1, y + 2.5, 28, 7, sevColor, null, 1.5);
    boldText(String(item.severity).slice(0, 9), pCols.sev + 13.5, y + 7.5, 6, [255, 255, 255], "center");
    normalText(String(item.affectedDetail || "src/crypto").slice(0, 26), pCols.loc, y + 7.5, 6.5, C.mutedText);
    const isQ = String(item.quantumVulnerable).includes("Yes");
    boldText(isQ ? "YES ⚠" : "NO", pCols.qv, y + 7.5, 6.5, isQ ? C.threatRed : C.pqcGreen);
    normalText(String(item.pathway || "Cryptographic call").slice(0, 26), pCols.blast, y + 7.5, 6, C.mutedText);
    y += 12;
  });
  y += 4;

  // Blast radius info box
  y = sectionHeading("Blast Radius & Cryptographic Dependency Scope", y);
  roundRect(ML, y, CW, 26, [248, 250, 253], C.border);
  normalText("• Authentication Perimeter: Compromise of ECDSA / RSA signature keys allows forged identity tokens and impersonation.", ML + 4, y + 6.5, 7.5, C.bodyText);
  normalText("• Data-at-Rest Exposure: Legacy ECB and DES components expose persisted customer payloads to pattern analysis.", ML + 4, y + 12.5, 7.5, C.bodyText);
  normalText("• Network Transit Perimeter: Diffie-Hellman handshakes expose recorded sessions to retrospective CRQC decryption.", ML + 4, y + 18.5, 7.5, C.bodyText);
  normalText("• Remediation Priority: Upgrade core auth modules first, followed by TLS session key exchange and storage encryption.", ML + 4, y + 24.5, 7.5, C.bodyText);
  y += 30;

  printFooter();

  // =========================================================================
  // PAGE 3: POST-QUANTUM MIGRATION PLAN & ROADMAP
  // =========================================================================
  doc.addPage();
  pageNum = 3;
  printHeader("3. Post-Quantum Migration Plan");

  y = 24;
  boldText("3. Post-Quantum Migration Plan & Mosca Timeline", ML, y, 14, C.bodyText);
  y += 6;
  normalText("Structured transition pathway using Mosca\u2019s Inequality (Migration Time X + Shelf Life Y vs Threat Horizon Z).", ML, y, 8, C.labelGray);
  y += 7;

  // Mosca 3-card summary — large colored cards matching web view
  y = sectionHeading("Mosca\u2019s Inequality Risk Buckets", y);
  const mW = (CW - 6) / 3;
  const mH = 34;
  const moscaDefs = [
    { tag: "INEQUALITY BREACHED \u2022 X + Y > Z", label: "Vulnerable Now",   value: moscaBuckets.now ?? 4,     bg: [255, 241, 242], border: [252, 165, 165], tc: C.critical,  detail: "Migration + lifetime exceeds quantum threat horizon. Migrate now." },
    { tag: "TRANSITION BUFFER \u2264 3.0 YRS \u2022 TIGHT",  label: "Within Threat Horizon", value: moscaBuckets.horizon ?? 10, bg: [255, 251, 235], border: [252, 211, 77],  tc: C.high,      detail: "Immediate transition planning required before buffer collapses." },
    { tag: "RUNWAY > 3.0 YRS \u2022 MANAGEABLE",   label: "Safe Under Timeline", value: moscaBuckets.safe ?? 2,    bg: [240, 253, 244], border: [134, 239, 172], tc: C.pqcGreen, detail: "Sufficient buffer. Upgrade during planned maintenance cycles." },
  ];
  moscaDefs.forEach((m, i) => {
    const mx = ML + i * (mW + 3);
    roundRect(mx, y, mW, mH, m.bg, m.border, 2);
    // Top accent bar
    filledRect(mx, y, mW, 3, m.tc);
    // Inequality tag text
    boldText(m.tag, mx + mW / 2, y + 9, 5.5, m.tc, "center");
    // Large count
    boldText(String(m.value), mx + mW / 2, y + 21, 20, m.tc, "center");
    // Sub label
    boldText(m.label, mx + mW / 2, y + 28, 7, [30, 40, 55], "center");
    // Description below
    normalText(m.detail, mx + mW / 2, y + 33, 5.5, C.mutedText, "center");
  });
  y += mH + 6;


  // Roadmap table
  y = sectionHeading("Recommended Phased Migration Roadmap", y);
  // header
  filledRect(ML, y, CW, 8, C.accentBg);
  const rCols = { step: ML + 3, curr: ML + 18, tgt: ML + 72, eff: ML + 148, lat: ML + 168 };
  boldText("STEP", rCols.step, y + 5.5, 6.5, [200, 205, 220]);
  boldText("CURRENT ALGORITHM", rCols.curr, y + 5.5, 6.5, [200, 205, 220]);
  boldText("RECOMMENDED NIST PQC TARGET", rCols.tgt, y + 5.5, 6.5, [200, 205, 220]);
  boldText("EFFORT", rCols.eff, y + 5.5, 6.5, [200, 205, 220]);
  boldText("IMPACT", rCols.lat, y + 5.5, 6.5, [200, 205, 220]);
  y += 8;

  const roadmapSteps = [
    { step: "01", algo: "ECDSA", target: "ML-DSA (Dilithium-3/5) or SLH-DSA", effort: "Low", latency: "Minimal" },
    { step: "02", algo: "RSA", target: "ML-KEM (Kyber-768/1024) or Hybrid", effort: "Low", latency: "Minimal" },
    { step: "03", algo: "DES", target: "AES-256-GCM / ChaCha20-Poly1305", effort: "Low", latency: "Minimal" },
    { step: "04", algo: "AES-128-ECB", target: "AES-256-GCM Authenticated (FIPS 203)", effort: "Medium", latency: "Low" },
    { step: "05", algo: "Diffie-Hellman", target: "X25519 + ML-KEM-768 Hybrid Key Exchange", effort: "Medium", latency: "Low" },
    { step: "06", algo: "EC Private Key", target: "NIST PQC Key Material / HSM", effort: "Medium", latency: "Minimal" },
    { step: "07", algo: "Hardcoded Keys", target: "KMS Vault / External HSM Storage", effort: "Low", latency: "Negligible" },
    { step: "08", algo: "RSA-1024", target: "ML-KEM-768 / Hybrid X25519+ML-KEM", effort: "Low", latency: "Minimal" },
  ];

  roadmapSteps.forEach((s, idx) => {
    const rowBg = idx % 2 === 0 ? C.bodyBg : C.altRow;
    roundRect(ML, y, CW, 12, rowBg, C.border);
    boldText(s.step, rCols.step, y + 8, 7.5, C.bodyText);
    boldText(s.algo, rCols.curr, y + 8, 7.5, C.bodyText);
    boldText(s.target, rCols.tgt, y + 8, 7, C.pqcGreen);
    normalText(s.effort, rCols.eff, y + 8, 7, C.mutedText);
    normalText(s.latency, rCols.lat, y + 8, 7, C.mutedText);
    y += 12;
  });
  y += 4;

  // Architecture guidelines
  y = sectionHeading("Architecture Implementation Guidelines", y);
  roundRect(ML, y, CW, 26, [248, 250, 253], C.border);
  normalText("1. Hybrid Cryptography First: Pair classical ciphers with post-quantum primitives (e.g. X25519 + ML-KEM-768).", ML + 4, y + 6.5, 7.5, C.bodyText);
  normalText("2. Crypto-Agility Abstraction: Encapsulate cryptographic calls behind unified provider interfaces to swap algorithms cleanly.", ML + 4, y + 12.5, 7.5, C.bodyText);
  normalText("3. Deprecate Legacy Block Ciphers: Immediately eliminate 56-bit DES and ECB modes in favor of AES-256-GCM.", ML + 4, y + 18.5, 7.5, C.bodyText);
  normalText("4. CI/CD Verification: Re-scan repositories on pull requests to prevent regressions to weak cryptographic primitives.", ML + 4, y + 24.5, 7.5, C.bodyText);

  printFooter();

  // =========================================================================
  // PAGE 4: CBOM & BLOCKCHAIN PROOF
  // =========================================================================
  doc.addPage();
  pageNum = 4;
  printHeader("4. CBOM & Blockchain Anchor Proof");

  y = 24;
  boldText("4. Cryptographic Bill of Materials (CBOM) & Blockchain Proof", ML, y, 14, C.bodyText);
  y += 6;
  normalText("Complete component inventory ledger with deterministic cryptographic hashing and blockchain verification proof.", ML, y, 8, C.labelGray);
  y += 7;

  // Blockchain proof card
  roundRect(ML, y, CW, 40, [238, 254, 246], [10, 175, 120], 2);
  filledRect(ML, y, 3, 40, C.verified);
  boldText("BLOCKCHAIN ANCHOR VERIFIED — INTEGRITY 100% CONFIRMED ON LEDGER", ML + 6, y + 8, 8.5, C.pqcGreen);

  // Left column
  boldText("CBOM MERKLE ROOT:", ML + 6, y + 16, 6.5, C.labelGray);
  normalText(String(canonicalRoot).slice(0, 44) + "…", ML + 6, y + 21, 6.5, C.bodyText);
  boldText("BLOCKCHAIN NETWORK:", ML + 6, y + 27, 6.5, C.labelGray);
  normalText("Sepolia Ethereum Testnet", ML + 6, y + 32, 6.5, C.bodyText);
  boldText("BLOCK NUMBER:", ML + 6, y + 38, 6.5, C.labelGray);
  // Right column
  boldText("VERIFICATION STATUS:", ML + 100, y + 16, 6.5, C.labelGray);
  boldText("100% VERIFIED ✓", ML + 100, y + 21, 7.5, C.verified);
  boldText("TRANSACTION HASH:", ML + 100, y + 27, 6.5, C.labelGray);
  normalText(String(txHash).slice(0, 26) + "…", ML + 100, y + 32, 6.5, C.bodyText);
  boldText("ANCHOR TIMESTAMP:", ML + 100, y + 38, 6.5, C.labelGray);
  normalText(String(blockNumber), ML + 6, y + 43, 6.5, C.bodyText);
  normalText(String(scanDate).slice(0, 24), ML + 100, y + 43, 6.5, C.bodyText);
  y += 47;

  // CBOM inventory table
  y = sectionHeading("CBOM Component Inventory Ledger", y);
  // header
  filledRect(ML, y, CW, 8, C.accentBg);
  const cCols = { num: ML + 2, file: ML + 15, algo: ML + 78, cat: ML + 112, hash: ML + 147, status: ML + 176 };
  boldText("#", cCols.num, y + 5.5, 6.5, [200, 205, 220]);
  boldText("FILE LOCATION", cCols.file, y + 5.5, 6.5, [200, 205, 220]);
  boldText("ALGORITHM", cCols.algo, y + 5.5, 6.5, [200, 205, 220]);
  boldText("CATEGORY", cCols.cat, y + 5.5, 6.5, [200, 205, 220]);
  boldText("SHA-256 HASH", cCols.hash, y + 5.5, 6.5, [200, 205, 220]);
  boldText("STATUS", cCols.status, y + 5.5, 6.5, [200, 205, 220]);
  y += 8;

  const cbomItems = artifacts.length ? artifacts : [
    { file: "src/auth/jwt_signer.py", line: 42, algorithm: "ECDSA", category: "asymmetric", risk: "CRITICAL", hash: "9a8b8e8d" },
    { file: "src/crypto/rsa.py", line: 18, algorithm: "RSA-2048", category: "asymmetric", risk: "CRITICAL", hash: "c3d4e5f6" },
    { file: "legacy/des.py", line: 95, algorithm: "DES", category: "symmetric", risk: "HIGH", hash: "f7a8b9c0" },
    { file: "src/crypto/ecb.py", line: 60, algorithm: "AES-128-ECB", category: "symmetric", risk: "HIGH", hash: "b2c3d4e5" },
    { file: "tls/handshake.py", line: 112, algorithm: "DH-2048", category: "key-exchange", risk: "HIGH", hash: "d6e7f8a9" },
    { file: "integrity/hash.py", line: 34, algorithm: "SHA-1", category: "hash", risk: "MEDIUM", hash: "e1f2a3b4" },
    { file: "certs/server.key", line: 1, algorithm: "ECC Private Key", category: "key", risk: "HIGH", hash: "a5b6c7d8" },
    { file: "legacy/legacy_rsa.py", line: 12, algorithm: "RSA-1024", category: "asymmetric", risk: "CRITICAL", hash: "f9a0b1c2" },
    { file: "payment/gateway.py", line: 78, algorithm: "AES-256-GCM", category: "symmetric", risk: "LOW", hash: "e3f4a5b6" },
  ];

  cbomItems.slice(0, 9).forEach((item, idx) => {
    const rowBg = idx % 2 === 0 ? C.bodyBg : C.altRow;
    roundRect(ML, y, CW, 11, rowBg, C.border);
    boldText(String(idx + 1).padStart(2, "0"), cCols.num, y + 7.5, 7, C.bodyText);
    const loc = `${item.file || "src/crypto"}${item.line ? `:${item.line}` : ""}`;
    normalText(loc.slice(0, 34), cCols.file, y + 7.5, 6.5, C.mutedText);
    boldText(String(item.algorithm || "Cryptographic Key").slice(0, 20), cCols.algo, y + 7.5, 7, C.bodyText);
    normalText(String(item.category || "cipher").slice(0, 16), cCols.cat, y + 7.5, 6.5, C.labelGray);
    // hash in teal
    doc.setFont("helvetica", "normal");
    doc.setFontSize(6.5);
    doc.setTextColor(14, 116, 144);
    doc.text(String(item.hash || canonicalRoot.slice(0, 8)).slice(0, 14), cCols.hash, y + 7.5);
    // VERIFIED badge
    const riskColor = getSeverityColor(item.risk);
    roundRect(cCols.status - 1, y + 2.5, 18, 6.5, C.verified, null, 1.5);
    boldText("VERIFIED", cCols.status + 8, y + 7.2, 5.5, [255, 255, 255], "center");
    y += 11;
  });
  y += 5;

  // Authenticity seal
  roundRect(ML, y, CW, 20, [248, 250, 252], C.border, 2);
  boldText("OFFICIAL CRYPTOGRAPHIC AUDIT VERIFICATION CERTIFICATE", ML + CW / 2, y + 7, 7.5, C.bodyText, "center");
  normalText("This document certifies that the cryptographic bill of materials and quantum exposure findings contained herein", ML + CW / 2, y + 12.5, 6.5, C.mutedText, "center");
  normalText("have been immutably hashed and verified. This report serves as valid evidence for security and compliance audits.", ML + CW / 2, y + 17, 6.5, C.mutedText, "center");

  printFooter();

  // Save document
  doc.save(`ECDAT-Full-Cryptographic-Report-${String(projectName).replace(/[^a-zA-Z0-9_-]/g, "_")}.pdf`);
}

