const pptxgen = require("pptxgenjs");

const pres = new pptxgen();
pres.layout = "LAYOUT_16x9"; // 10" x 5.63"

// ---- palette -------------------------------------------------------------
const BG = "0B1437";
const WHITE = "FFFFFF";
const CYAN = "29D3F2";
const INDIGO = "4C6FFF";
const LINE = "1E2A5E";
const MUTED = "A8B2D9";
const F = "Arial";

// ---- masters -------------------------------------------------------------
pres.defineSlideMaster({
  title: "TITLE",
  background: { color: BG },
  objects: [
    { rect: { x: 0.4, y: 0.4, w: 9.2, h: 4.45, fill: { color: BG }, line: { color: LINE, width: 0.75 } } },
    { rect: { x: 0.4, y: 5.2, w: 0.06, h: 0.18, fill: { color: INDIGO } } },
  ],
});

pres.defineSlideMaster({
  title: "CONTENT",
  background: { color: BG },
  objects: [
    { rect: { x: 0.6, y: 1.02, w: 8.8, h: 0.02, fill: { color: LINE } } },
    { rect: { x: 0.6, y: 5.2, w: 0.06, h: 0.18, fill: { color: INDIGO } } },
  ],
});

let n = 0;
function content(title) {
  n += 1;
  const s = pres.addSlide({ masterName: "CONTENT" });
  s.addText(title, {
    x: 0.6, y: 0.32, w: 8.0, h: 0.6,
    fontSize: 22, bold: true, color: WHITE, fontFace: F,
  });
  s.addText(`${n}`, {
    x: 8.9, y: 5.13, w: 0.5, h: 0.3,
    fontSize: 9, color: MUTED, fontFace: F, align: "right",
  });
  s.addText("Quantum-Resilient Communication for CAVs", {
    x: 0.75, y: 5.13, w: 5.5, h: 0.3,
    fontSize: 8, color: MUTED, fontFace: F,
  });
  return s;
}

const bullets = (items) =>
  items.map((t) => ({
    text: t,
    options: { bullet: { code: "2022" }, color: WHITE, fontSize: 14, fontFace: F, paraSpaceAfter: 8 },
  }));

// =========================================================== 1. TITLE
{
  const s = pres.addSlide({ masterName: "TITLE" });
  s.addText("Quantum-Resilient Authenticated Communication\nfor Connected and Autonomous Vehicles", {
    x: 0.8, y: 1.15, w: 8.4, h: 1.2,
    fontSize: 26, bold: true, color: WHITE, fontFace: F, align: "center", lineSpacingMultiple: 1.1,
  });
  s.addText("using ML-KEM (FIPS 203), ML-DSA (FIPS 204) and Adaptive Grouping Score PBFT", {
    x: 0.8, y: 2.42, w: 8.4, h: 0.4,
    fontSize: 13, color: CYAN, fontFace: F, align: "center",
  });
  s.addText("Final Year Project  |  Zeroth Review  |  B.Tech Information Technology", {
    x: 0.8, y: 3.05, w: 8.4, h: 0.3,
    fontSize: 11, color: MUTED, fontFace: F, align: "center",
  });
  s.addText(
    "Team:  <Name 1>  ·  <Name 2>  ·  <Name 3>\nGuide:  <Guide Name>\n<Department>,  <College Name>",
    { x: 0.8, y: 3.5, w: 8.4, h: 1.0, fontSize: 11, color: WHITE, fontFace: F, align: "center", lineSpacingMultiple: 1.25 }
  );
}

// =========================================================== 2. PROBLEM
{
  const s = content("The Problem");
  s.addText(
    "Connected vehicles exchange safety-critical messages — braking, hazard, intersection entry — over open wireless links. These are secured today by ECDSA and ECDH.",
    { x: 0.6, y: 1.25, w: 8.8, h: 0.6, fontSize: 14, color: WHITE, fontFace: F }
  );
  s.addTable(
    [
      [
        { text: "Algorithm", options: { bold: true, color: CYAN } },
        { text: "Used for", options: { bold: true, color: CYAN } },
        { text: "Quantum attack", options: { bold: true, color: CYAN } },
        { text: "Status", options: { bold: true, color: CYAN } },
      ],
      ["ECDH-256", "Key exchange", "Shor", "Broken"],
      ["ECDSA-256", "Signatures", "Shor", "Broken"],
      ["RSA-3072", "Both", "Shor", "Broken"],
      ["AES-256", "Encryption", "Grover", "Survives"],
      ["SHA-3 / SHAKE", "Hashing", "Grover", "Survives"],
    ],
    {
      x: 0.6, y: 2.0, w: 8.8, colW: [1.9, 2.2, 2.3, 2.4],
      fontSize: 12, color: WHITE, fontFace: F,
      border: { type: "solid", color: LINE, pt: 0.5 },
      fill: { color: BG }, rowH: 0.32,
    }
  );
  s.addText(
    "Harvest now, decrypt later:  traffic recorded today can be decrypted once a quantum computer exists. For location history, that still matters in 2041.",
    { x: 0.6, y: 4.28, w: 8.8, h: 0.5, fontSize: 12, italic: true, color: CYAN, fontFace: F }
  );
}

// =========================================================== 3. THE GAP
{
  const s = content("The Replacements Exist — But They Are Large");
  s.addText("NIST standardised the replacements in August 2024.", {
    x: 0.6, y: 1.22, w: 8.8, h: 0.3, fontSize: 14, color: WHITE, fontFace: F,
  });
  s.addTable(
    [
      [
        { text: "", options: { bold: true, color: CYAN } },
        { text: "Classical", options: { bold: true, color: CYAN } },
        { text: "Post-quantum", options: { bold: true, color: CYAN } },
        { text: "Growth", options: { bold: true, color: CYAN } },
      ],
      ["Key exchange public key", "32 B  (ECDH)", "1,568 B  (ML-KEM-1024)", "49×"],
      ["Signature", "64 B  (ECDSA)", "3,309 B  (ML-DSA-65)", "52×"],
      ["Handshake on the wire", "~250 B", "6,494 B  (measured)", "26×"],
      ["802.11p frames needed", "1", "5", "5×"],
    ],
    {
      x: 0.6, y: 1.68, w: 8.8, colW: [2.7, 1.9, 2.6, 1.6],
      fontSize: 12, color: WHITE, fontFace: F,
      border: { type: "solid", color: LINE, pt: 0.5 },
      fill: { color: BG }, rowH: 0.34,
    }
  );
  s.addText("Vehicular constraint", {
    x: 0.6, y: 3.55, w: 8.8, h: 0.3, fontSize: 13, bold: true, color: CYAN, fontFace: F,
  });
  s.addText(
    "IEEE 802.11p safety beacons must be produced every 100 ms over a 6 Mbps short-range link.\n\nResearch question:  do the standardised post-quantum primitives still fit that budget?",
    { x: 0.6, y: 3.88, w: 8.8, h: 0.9, fontSize: 13, color: WHITE, fontFace: F, lineSpacingMultiple: 1.15 }
  );
}

// =========================================================== 4. BASE PAPER
{
  const s = content("Base Paper");
  s.addText(
    '"Quantum-resilient blockchain-enabled secure communication framework for connected autonomous vehicles using post-quantum cryptography"',
    { x: 0.6, y: 1.25, w: 8.8, h: 0.65, fontSize: 14, italic: true, color: CYAN, fontFace: F }
  );
  s.addText(
    "A. M. Aslam, A. Bhardwaj, R. Chaudhary\nVehicular Communications, Vol. 52, Article 100880, 2025  ·  Elsevier\nDOI: 10.1016/j.vehcom.2025.100880  ·  Bennett University, Greater Noida",
    { x: 0.6, y: 1.95, w: 8.8, h: 0.75, fontSize: 12, color: MUTED, fontFace: F, lineSpacingMultiple: 1.2 }
  );
  s.addText("What it proposes", {
    x: 0.6, y: 2.78, w: 8.8, h: 0.3, fontSize: 13, bold: true, color: CYAN, fontFace: F,
  });
  s.addText(
    bullets([
      "A four-layer CAV architecture: vehicles, RSU / edge, consensus, cloud",
      "Kyber (ML-KEM) session keys for V2V and V2I links",
      "AGS-PBFT — a consensus protocol where nodes are scored on behaviour (+1 agree, −5 disagree) and promoted or demoted against μ ± σ thresholds every 50 requests",
      "A tamper-proof ledger of validated traffic transactions",
    ]),
    { x: 0.6, y: 3.1, w: 8.8, h: 1.7 }
  );
}

// =========================================================== 5. OBJECTIVE
{
  const s = content("Our Objective");
  s.addText(
    "Implement the base paper's framework and determine whether NIST post-quantum authentication meets the 100 ms vehicular safety-message deadline under realistic road mobility.",
    { x: 0.6, y: 1.3, w: 8.8, h: 0.75, fontSize: 15, color: CYAN, fontFace: F, lineSpacingMultiple: 1.15 }
  );
  s.addText("Specific objectives", {
    x: 0.6, y: 2.15, w: 8.8, h: 0.3, fontSize: 13, bold: true, color: CYAN, fontFace: F,
  });
  s.addText(
    bullets([
      "Registration and enrolment of vehicles, RSUs, edge and cloud servers with a Trusted Authority",
      "Authenticated key establishment: ML-KEM-1024 + ML-DSA-65 + HKDF–SHA3-256 + AES-256-GCM",
      "AGS-PBFT consensus with score-based node regrouping, and a hash-linked ledger",
      "Evaluation over SUMO mobility, 50–300 vehicles, against ECDH/ECDSA and standard PBFT baselines",
      "Determine whether lower parameter sets (ML-KEM-768 / ML-DSA-44) meet the budget where level 5 does not",
    ]),
    { x: 0.6, y: 2.48, w: 8.8, h: 2.3 }
  );
}

// =========================================================== 6. WHAT WE BUILD
{
  const s = content("What We Implement");
  s.addTable(
    [
      [
        { text: "Module", options: { bold: true, color: CYAN } },
        { text: "Function", options: { bold: true, color: CYAN } },
        { text: "Status", options: { bold: true, color: CYAN } },
      ],
      ["entities.py", "Trusted Authority, vehicles, RSUs, edge and cloud servers", "Week 4"],
      ["handshake.py", "Mutual authentication and session-key establishment", "Running"],
      ["consensus.py", "AGS-PBFT: scoring, μ ± σ regrouping, four-phase agreement", "Weeks 6–8"],
      ["ledger.py", "Hash-linked blocks of validated traffic transactions", "Week 8"],
      ["mobility.py", "SUMO + TraCI vehicle movement on a real road network", "Week 9"],
      ["network.py", "IEEE 802.11p delay, range and contention model", "Week 10"],
      ["benchmark.py", "Metrics, baselines, attack tests, figures", "Week 11"],
    ],
    {
      x: 0.6, y: 1.3, w: 8.8, colW: [1.9, 5.1, 1.8],
      fontSize: 11.5, color: WHITE, fontFace: F,
      border: { type: "solid", color: LINE, pt: 0.5 },
      fill: { color: BG }, rowH: 0.3,
    }
  );
  s.addText("Approximately 2,600 lines of Python.  Two modules already run.", {
    x: 0.6, y: 3.75, w: 8.8, h: 0.3, fontSize: 12, italic: true, color: CYAN, fontFace: F,
  });
  s.addText(
    "Note: the base paper's Algorithm 1 and Algorithm 2 listings are incomplete — Algorithm 1 defines the shared secret in terms of itself, and consensus messages are signed using a key encapsulation mechanism, which has no signing operation. We reconstruct both from FIPS 203 and FIPS 204 and document every deviation.",
    { x: 0.6, y: 4.1, w: 8.8, h: 0.8, fontSize: 11, color: MUTED, fontFace: F, lineSpacingMultiple: 1.1 }
  );
}

// =========================================================== 7. TOOLS
{
  const s = content("Tools — All Free and Open Source");
  s.addTable(
    [
      [
        { text: "Purpose", options: { bold: true, color: CYAN } },
        { text: "Tool", options: { bold: true, color: CYAN } },
        { text: "Licence", options: { bold: true, color: CYAN } },
      ],
      ["Language", "Python 3.9+", "PSF"],
      ["Key establishment (FIPS 203)", "kyber-py  —  ML-KEM-1024", "MIT / Apache-2.0"],
      ["Authentication (FIPS 204)", "dilithium-py  —  ML-DSA-65", "MIT / Apache-2.0"],
      ["Record encryption", "pycryptodome  —  AES-256-GCM", "BSD"],
      ["Traffic mobility", "Eclipse SUMO + TraCI", "EPL-2.0"],
      ["Network simulation", "SimPy", "MIT"],
      ["Road network", "OpenStreetMap", "ODbL"],
      ["Analysis and figures", "pandas, NumPy, Matplotlib", "BSD"],
    ],
    {
      x: 0.6, y: 1.28, w: 8.8, colW: [3.1, 3.6, 2.1],
      fontSize: 11.5, color: WHITE, fontFace: F,
      border: { type: "solid", color: LINE, pt: 0.5 },
      fill: { color: BG }, rowH: 0.29,
    }
  );
  s.addText(
    "No licence cost, no GPU, no accelerator. Measured peak memory under 10 MB — runs on any laptop.",
    { x: 0.6, y: 4.05, w: 8.8, h: 0.3, fontSize: 12, italic: true, color: CYAN, fontFace: F }
  );
  s.addText(
    "Substituted deliberately:  OMNeT++ / Veins → SimPy analytic 802.11p model  ·  Hyperledger Fabric 2.2 → direct Python ledger (Fabric 2.2 orders via Raft and cannot host PBFT)  ·  PQClean C → pure-Python, ACVP-validated",
    { x: 0.6, y: 4.4, w: 8.8, h: 0.55, fontSize: 10.5, color: MUTED, fontFace: F, lineSpacingMultiple: 1.1 }
  );
}

// =========================================================== 8. RESULTS
{
  const s = content("Preliminary Results — Already Measured");
  s.addTable(
    [
      [
        { text: "Operation", options: { bold: true, color: CYAN } },
        { text: "Mean (ms)", options: { bold: true, color: CYAN } },
        { text: "SD (ms)", options: { bold: true, color: CYAN } },
      ],
      ["ML-KEM-1024 key generation", "3.965", "0.113"],
      ["ML-KEM-1024 encapsulation", "5.025", "0.135"],
      ["ML-KEM-1024 decapsulation", "6.562", "0.138"],
      ["ML-DSA-65 signing", "47.179", "31.923"],
      ["ML-DSA-65 verification", "8.726", "0.255"],
      ["AES-256-GCM encryption, 1 KB", "0.040", "0.015"],
    ],
    {
      x: 0.6, y: 1.28, w: 5.5, colW: [3.1, 1.3, 1.1],
      fontSize: 11.5, color: WHITE, fontFace: F,
      border: { type: "solid", color: LINE, pt: 0.5 },
      fill: { color: BG }, rowH: 0.29,
    }
  );
  s.addText("Full V2R handshake", {
    x: 6.35, y: 1.32, w: 3.05, h: 0.25, fontSize: 12, bold: true, color: CYAN, fontFace: F,
  });
  s.addText("48.23 ms\n6,494 bytes\n5 frames\n\nBudget: 100 ms", {
    x: 6.35, y: 1.62, w: 3.05, h: 1.4, fontSize: 13, color: WHITE, fontFace: F, lineSpacingMultiple: 1.2,
  });
  s.addText("Finding", {
    x: 0.6, y: 3.35, w: 8.8, h: 0.3, fontSize: 13, bold: true, color: CYAN, fontFace: F,
  });
  s.addText(
    bullets([
      "Signature generation dominates the handshake — not key exchange, as usually assumed",
      "Signing variance is high (± 32 ms) because ML-DSA uses rejection sampling; the worst case may breach 100 ms",
      "This shapes the project: the question becomes which parameter sets keep the tail inside budget",
    ]),
    { x: 0.6, y: 3.68, w: 8.8, h: 1.15 }
  );
}

// =========================================================== 9. TIMELINE
{
  const s = content("Twelve-Week Plan");
  s.addTable(
    [
      [
        { text: "Weeks", options: { bold: true, color: CYAN } },
        { text: "Milestone", options: { bold: true, color: CYAN } },
      ],
      ["1 – 2", "Fundamentals; study base paper; reconstruct Algorithm 1 and 2"],
      ["3", "Environment; validate libraries against NIST ACVP test vectors"],
      ["4 – 5", "Registration, enrolment, tokens, revocation, timestamp freshness"],
      ["6", "Handshake: ML-KEM + ML-DSA + HKDF + AES-256-GCM"],
      ["7 – 8", "AGS-PBFT consensus and hash-linked ledger"],
      ["9", "SUMO road network and TraCI mobility integration"],
      ["10", "IEEE 802.11p link model; full system integration"],
      ["11", "Baselines, attack harness, experiments, figures"],
      ["12", "Report, demonstration, viva"],
    ],
    {
      x: 0.6, y: 1.28, w: 8.8, colW: [1.3, 7.5],
      fontSize: 11.5, color: WHITE, fontFace: F,
      border: { type: "solid", color: LINE, pt: 0.5 },
      fill: { color: BG }, rowH: 0.3,
    }
  );
  s.addText("Team split:  cryptography  ·  consensus  ·  simulation and evaluation", {
    x: 0.6, y: 4.42, w: 8.8, h: 0.3, fontSize: 12, italic: true, color: CYAN, fontFace: F,
  });
}

// =========================================================== 10. OUTCOMES
{
  const s = content("Expected Deliverables");
  s.addText(
    bullets([
      "A working, documented implementation of the framework, released as open source",
      "Independently measured performance of ML-KEM and ML-DSA across all parameter sets, with a correct ECDH / ECDSA baseline",
      "A determination of whether post-quantum authentication meets the 100 ms V2X deadline, and under which parameter sets",
      "Comparison of AGS-PBFT against standard PBFT for message count, latency and fault tolerance at 50–300 vehicles",
      "Demonstrated resistance to replay, tampering, impersonation and downgrade attacks",
      "Live demonstration: SUMO road network, running handshakes, consensus, and rejected attacks",
    ]),
    { x: 0.6, y: 1.3, w: 8.8, h: 2.6 }
  );
  s.addText("Scope boundary", {
    x: 0.6, y: 3.95, w: 8.8, h: 0.3, fontSize: 13, bold: true, color: CYAN, fontFace: F,
  });
  s.addText(
    "Simulation-based study. Not in scope: deployment on vehicle hardware, side-channel-hardened implementations, or formal protocol verification. The pure-Python cryptographic libraries are documented by their authors as educational and not constant-time — appropriate for a functional and performance study, and stated as a limitation.",
    { x: 0.6, y: 4.26, w: 8.8, h: 0.75, fontSize: 10.5, color: MUTED, fontFace: F, lineSpacingMultiple: 1.1 }
  );
}

// =========================================================== 11. CLOSE
{
  const s = pres.addSlide({ masterName: "TITLE" });
  s.addText("Request for Approval", {
    x: 0.8, y: 1.6, w: 8.4, h: 0.6,
    fontSize: 28, bold: true, color: WHITE, fontFace: F, align: "center",
  });
  s.addText(
    "Base paper:  Vehicular Communications 52 (2025) 100880, Elsevier\nScope:  simulation-based implementation and evaluation, 12 weeks\nTools:  entirely free and open source\nStatus:  handshake implemented and measured",
    { x: 0.8, y: 2.4, w: 8.4, h: 1.2, fontSize: 13, color: WHITE, fontFace: F, align: "center", lineSpacingMultiple: 1.35 }
  );
  s.addText("Thank you", {
    x: 0.8, y: 4.05, w: 8.4, h: 0.4, fontSize: 15, color: CYAN, fontFace: F, align: "center",
  });
}

pres
  .writeFile({ fileName: "Zeroth-Review-Abstract.pptx" })
  .then((f) => console.log("Created:", f))
  .catch((e) => console.error(e));
