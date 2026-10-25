
"use strict";

const $ = (id) => document.getElementById(id);
const input = $("messageInput");
let lastReport = null;
let selectedImageUrl = null;

const examples = {
  job: "Congratulations! You are selected for a remote internship with a salary of ₹45,000 per week. No interview needed. Pay a refundable registration fee of ₹999 today to secure your position. Limited seats! Send your Aadhaar and bank details on WhatsApp immediately.",
  payment: "URGENT: Your bank account will be blocked in 2 hours. Verify KYC immediately using this link and share the OTP with our support agent to prevent suspension. Do not ignore this message.",
  safe: "Hi! The project review meeting has been moved to Thursday at 2:30 PM in Room 204. Please bring your draft slides. If you cannot attend, reply to this email and we will share the notes."
};

const rules = [
  {
    name: "Urgency or pressure tactics", weight: 18,
    patterns: [/\b(urgent|immediately|right now|within \d+ hours?|limited time|act now|last chance|do not ignore|today only|expires in \d+ hours?)\b/i],
    explanation: "The message creates pressure to act quickly. Urgency can reduce the time available for independent verification."
  },
  {
    name: "Upfront payment request", weight: 24,
    patterns: [/\b(registration fee|processing fee|refundable fee|pay (?:a |the )?(?:fee|deposit)|send (?:the )?(?:money|payment)|pay now|security deposit|activation fee|advance payment)\b/i],
    explanation: "A payment request connected to a job, prize, account or opportunity should be checked independently."
  },
  {
    name: "Sensitive information mentioned", weight: 25,
    patterns: [/\b(password|otp|one[- ]time password|pin number|cvv|bank details|aadhaar|social security number|full card number)\b/i],
    explanation: "The text mentions sensitive information. Never share passwords, OTPs, PINs or CVV codes with a sender."
  },
  {
    name: "Link or online verification request", weight: 18,
    patterns: [/https?:\/\/[^\s<>"']+/i, /\b(click (?:this |the )?link|verify (?:your )?(?:account|kyc|identity) (?:here|now|immediately)|link below)\b/i],
    explanation: "Unexpected links may lead to lookalike websites. Open the official site independently instead of trusting the message link."
  },
  {
    name: "Unusually attractive reward or earnings", weight: 16,
    patterns: [/\b(guaranteed (?:job|income|profit|return)|earn \$?\d[\d,]*(?: per week| weekly| daily)?|salary of [₹$]?\d[\d,]* per week|you (?:have )?won|prize winner|no interview needed|risk[- ]free profit|double your money)\b/i],
    explanation: "Unusually high rewards or jobs without a credible selection process can be warning signs. Verify the organization."
  },
  {
    name: "Threat or account suspension claim", weight: 20,
    patterns: [/\b(account will be (?:blocked|suspended)|account (?:blocked|suspended)|will be arrested|legal action|account closure|kyc expires|service will be terminated|warrant issued)\b/i],
    explanation: "Threats about account closure or legal consequences may pressure people into acting without checking."
  },
  {
    name: "Unusual contact or secrecy request", weight: 12,
    patterns: [/\b(on whatsapp|via whatsapp|telegram only|keep this confidential|do not tell anyone|personal account|message me privately|only contact me here)\b/i],
    explanation: "Moving a formal process to an unofficial channel can make independent verification harder."
  },
  {
    name: "Institution or authority claim", weight: 10,
    patterns: [/\b(bank support|government officer|customs department|tax department|police department|official verification team|account security team|income tax department)\b/i],
    explanation: "Mentioning a bank, government office or authority does not prove the sender represents it."
  }
];

function matchRule(text, rule) {
  for (const pattern of rule.patterns) {
    const match = pattern.exec(text);
    if (match) return match[0].trim();
  }
  return null;
}

function inspectUrl(rawValue) {
  const raw = rawValue.trim();
  const findings = [];

  if (!raw) {
    return { valid: false, input: raw, findings: ["No URL supplied."] };
  }

  let candidate = raw;
  if (!/^[a-zA-Z][a-zA-Z\d+.-]*:/.test(candidate)) {
    candidate = "https://" + candidate;
  }

  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    return {
      valid: false,
      input: raw,
      findings: ["This text could not be parsed as a URL. Check its spelling and format."]
    };
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    findings.push("This is not a standard HTTP or HTTPS web link.");
  }

  if (parsed.protocol === "http:") {
    findings.push("The link uses HTTP rather than encrypted HTTPS.");
  }

  if (parsed.username || parsed.password) {
    findings.push("The URL contains user-info before the hostname, which can be used to disguise a destination.");
  }

  if (parsed.hostname.startsWith("xn--") || parsed.hostname.split(".").some(part => part.startsWith("xn--"))) {
    findings.push("The hostname contains punycode. Check for lookalike characters carefully.");
  }

  const host = parsed.hostname.toLowerCase();
  const trustedLike = ["google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com", "github.com"];
  const lookalike = trustedLike.some(domain =>
    host !== domain && !host.endsWith("." + domain) &&
    host.includes(domain.split(".")[0]) && host.length > domain.length
  );

  if (lookalike) {
    findings.push("The hostname resembles a well-known brand name. This heuristic is not proof of impersonation.");
  }

  if (host.startsWith("xn--") || host.split(".").some(part => part.includes("--"))) {
    findings.push("The hostname contains unusual hyphen patterns. Verify the exact domain independently.");
  }

  if (parsed.hostname.split(".").length >= 5) {
    findings.push("The hostname has several subdomains. Check which domain actually owns the site.");
  }

  if (parsed.hostname.includes(" ")) {
    findings.push("The hostname contains spaces and is unusual.");
  }

  if (parsed.hostname.length > 60) {
    findings.push("The hostname is unusually long. Check it carefully before proceeding.");
  }

  if (parsed.port && !["80", "443"].includes(parsed.port)) {
    findings.push("The URL specifies a non-standard web port.");
  }

  if (parsed.hostname === "localhost" || parsed.hostname.endsWith(".local")) {
    findings.push("This appears to be a local-network address, not a typical public website.");
  }

  if (findings.length === 0) {
    findings.push("No obvious structural warning pattern was detected. This does not mean the URL is safe.");
  }

  return {
    valid: true,
    input: raw,
    normalized: parsed.href,
    protocol: parsed.protocol,
    hostname: parsed.hostname,
    findings
  };
}

function extractUrls(text) {
  const matches = text.match(/(?:https?:\/\/|www\.)[^\s<>"']+/gi) || [];
  return [...new Set(matches.map(item => item.replace(/[),.!?;]+$/g, "")))].slice(0, 20);
}

function analyze(text) {
  const signals = [];
  for (const rule of rules) {
    const evidence = matchRule(text, rule);
    if (evidence) signals.push({ name: rule.name, weight: rule.weight, evidence, explanation: rule.explanation });
  }

  const urls = extractUrls(text).map(inspectUrl);
  let score = signals.reduce((sum, signal) => sum + signal.weight, 0);
  if (signals.length >= 3) score += 8;
  if (urls.some(url => url.valid && url.findings.some(f => /HTTP rather than|punycode|resembles a well-known|non-standard web port/i.test(f)))) score += 10;
  score = Math.min(98, score);

  let level, title, summary, color;
  if (score >= 55) {
    level = "HIGHER CONCERN"; title = "Pause and verify";
    summary = "Several warning patterns matched. Avoid payment, links and disclosure of sensitive information until you verify the claims independently.";
    color = "var(--danger)";
  } else if (score >= 25) {
    level = "SOME CONCERN"; title = "Review carefully";
    summary = "One or more warning patterns matched. Verify the sender and claims through a separate trusted source.";
    color = "var(--warning)";
  } else if (score > 0) {
    level = "SOME SIGNALS"; title = "A few things to check";
    summary = "A warning pattern matched. The text alone cannot establish whether the message is genuine.";
    color = "var(--warning)";
  } else {
    level = "NO MATCHING RULES"; title = "No obvious flags found";
    summary = "No configured warning pattern matched. This does not prove that the message is legitimate or safe.";
    color = "var(--success)";
  }

  return { score, level, title, summary, color, signals, urls };
}

function getSteps(result) {
  const names = result.signals.map(s => s.name);
  const steps = [];
  if (names.includes("Upfront payment request")) steps.push("Do not pay a fee or deposit before independently verifying the organization.");
  if (names.includes("Sensitive information mentioned")) steps.push("Never share an OTP, password, PIN or CVV. If already shared, secure the affected account promptly.");
  if (names.includes("Link or online verification request") || result.urls.length) steps.push("Avoid unexpected message links. Navigate to the official website or app independently.");
  if (names.includes("Unusually attractive reward or earnings")) steps.push("Verify the offer with the organization's official website and independently found contact details.");
  if (names.includes("Threat or account suspension claim")) steps.push("Contact the relevant bank or service using its official app, card or website.");
  if (names.includes("Unusual contact or secrecy request")) steps.push("Verify through an independent official contact channel.");
  steps.push("Check the sender address, domain spelling and context using a separate trusted source.");
  steps.push("If you sent money or exposed account details, contact your bank or service promptly.");
  return [...new Set(steps)].slice(0, 5);
}

function createSignalCard(signal) {
  const card = document.createElement("article");
  card.className = "signal-card";
  const heading = document.createElement("div");
  heading.className = "signal-head";
  const icon = document.createElement("span");
  icon.className = "signal-icon";
  icon.textContent = "!";
  const title = document.createElement("span");
  title.textContent = signal.name;
  heading.append(icon, title);

  const description = document.createElement("p");
  description.textContent = signal.explanation;
  const quote = document.createElement("blockquote");
  quote.textContent = `Matched text: “${signal.evidence}”`;
  card.append(heading, description, quote);
  return card;
}

function renderUrlResult(target, urlResult) {
  target.replaceChildren();
  target.classList.remove("hidden");

  const heading = document.createElement("h3");
  heading.textContent = urlResult.valid ? "URL structure review" : "URL format review";
  target.append(heading);

  if (urlResult.valid) {
    const host = document.createElement("p");
    host.textContent = `Hostname: ${urlResult.hostname}`;
    target.append(host);
  }

  const list = document.createElement("ul");
  for (const finding of urlResult.findings) {
    const item = document.createElement("li");
    item.textContent = finding;
    list.append(item);
  }
  target.append(list);

  const note = document.createElement("p");
  note.textContent = "No network request was made to the supplied URL. These are local structural checks, not a reputation lookup.";
  target.append(note);
}

function renderAnalysis(text) {
  const result = analyze(text);
  const steps = getSteps(result);

  $("emptyState").classList.add("hidden");
  $("results").classList.remove("hidden");
  $("riskLabel").textContent = result.level;
  $("riskLabel").style.color = result.color;
  $("riskTitle").textContent = result.title;
  $("riskSummary").textContent = result.summary;
  $("riskScore").textContent = String(result.score);
  $("scoreRing").style.background =
    `conic-gradient(${result.color} ${result.score * 3.6}deg, #29344b ${result.score * 3.6}deg)`;
  $("scoreRing").setAttribute("aria-label", `Heuristic indicator score ${result.score} out of 100; not a probability.`);
  $("meterFill").style.width = `${result.score}%`;
  $("meterFill").style.background = result.color;
  $("signalCount").textContent = String(result.signals.length);
  $("urlCount").textContent = String(result.urls.length);

  $("disclaimer").textContent =
    "Rule-based heuristic only — not a probability, verified AI result or guarantee of safety. False positives and missed scams are possible.";

  const signalList = $("signalsList");
  signalList.replaceChildren();
  if (result.signals.length === 0) {
    const note = document.createElement("div");
    note.className = "no-signals";
    note.textContent = "No configured warning patterns matched. Still verify unexpected requests independently.";
    signalList.append(note);
  } else {
    result.signals.forEach(signal => signalList.append(createSignalCard(signal)));
  }

  const urlList = $("urlFindings");
  urlList.replaceChildren();
  if (!result.urls.length) {
    const note = document.createElement("div");
    note.className = "no-signals";
    note.textContent = "No obvious URL was detected in this message.";
    urlList.append(note);
  } else {
    result.urls.forEach(url => {
      const card = document.createElement("article");
      card.className = "signal-card";
      const title = document.createElement("div");
      title.className = "signal-head";
      title.textContent = url.hostname || url.input;
      card.append(title);
      const list = document.createElement("ul");
      url.findings.forEach(finding => {
        const item = document.createElement("li");
        item.textContent = finding;
        list.append(item);
      });
      card.append(list);
      urlList.append(card);
    });
  }

  const stepsList = $("nextSteps");
  stepsList.replaceChildren();
  steps.forEach(step => {
    const li = document.createElement("li");
    li.textContent = step;
    stepsList.append(li);
  });

  lastReport = {
    product: "TrustLens",
    reportType: "Rule-based prototype analysis",
    generatedAt: new Date().toISOString(),
    heuristicScore: result.score,
    scoreMeaning: "Heuristic indicator only; not a probability of fraud.",
    assessment: { level: result.level, title: result.title, summary: result.summary },
    signals: result.signals,
    urls: result.urls,
    recommendedSteps: steps,
    limitations: [
      "No real AI model is connected in this version.",
      "URL checks are local heuristics; no reputation service or network lookup is used.",
      "A low score does not establish that a message is safe.",
      "False positives and false negatives are possible."
    ]
  };

  $("resultPanel").scrollIntoView({
    behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
    block: "nearest"
  });
}

function runAnalysis(text) {
  const clean = text.trim();
  if (clean.length < 5) {
    $("inputError").textContent = "Enter a little more text before analyzing.";
    return false;
  }
  if (clean.length > 10000) {
    $("inputError").textContent = "Text is too long. Maximum length is 10,000 characters.";
    return false;
  }
  $("inputError").textContent = "";
  renderAnalysis(clean);
  return true;
}

input.addEventListener("input", () => {
  $("charCount").textContent = `${input.value.length.toLocaleString()} / 10,000 characters`;
  $("inputError").textContent = "";
});

document.querySelectorAll(".example-button").forEach(button => {
  button.addEventListener("click", () => {
    input.value = examples[button.dataset.example];
    input.dispatchEvent(new Event("input"));
    input.focus();
  });
});

$("clearBtn").addEventListener("click", () => {
  input.value = "";
  input.dispatchEvent(new Event("input"));
  $("inputError").textContent = "";
  input.focus();
});

$("analyzeBtn").addEventListener("click", () => runAnalysis(input.value));

$("reanalyzeBtn").addEventListener("click", () => {
  input.focus();
  input.scrollIntoView({ behavior: "smooth", block: "center" });
});

$("inspectUrlBtn").addEventListener("click", () => {
  const raw = $("urlInput").value;
  $("urlError").textContent = "";
  if (!raw.trim()) {
    $("urlError").textContent = "Enter a URL first.";
    return;
  }
  const result = inspectUrl(raw);
  renderUrlResult($("standaloneUrlResult"), result);
});

$("urlInput").addEventListener("keydown", event => {
  if (event.key === "Enter") $("inspectUrlBtn").click();
});

$("downloadReportBtn").addEventListener("click", () => {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `trustlens-report-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
});

$("screenshotInput").addEventListener("change", () => {
  const file = $("screenshotInput").files?.[0];
  $("ocrStatus").textContent = "";
  $("ocrBtn").disabled = true;
  $("useOcrTextBtn").disabled = true;

  if (selectedImageUrl) URL.revokeObjectURL(selectedImageUrl);
  selectedImageUrl = null;
  $("ocrPreviewWrap").classList.add("hidden");

  if (!file) {
    $("ocrStatus").textContent = "Select an image to begin.";
    return;
  }

  if (!["image/png", "image/jpeg", "image/webp"].includes(file.type)) {
    $("ocrStatus").textContent = "Unsupported format. Select a PNG, JPG or WebP image.";
    $("screenshotInput").value = "";
    return;
  }

  if (file.size > 8 * 1024 * 1024) {
    $("ocrStatus").textContent = "Image is too large. Please choose an image under 8 MB.";
    $("screenshotInput").value = "";
    return;
  }

  selectedImageUrl = URL.createObjectURL(file);
  $("ocrPreview").src = selectedImageUrl;
  $("ocrPreviewWrap").classList.remove("hidden");
  $("ocrStatus").textContent = "Image ready. Select Extract text to run OCR.";
  $("ocrBtn").disabled = false;
});

$("ocrBtn").addEventListener("click", async () => {
  const file = $("screenshotInput").files?.[0];
  if (!file) {
    $("ocrStatus").textContent = "Choose an image first.";
    return;
  }
  if (!window.Tesseract || typeof window.Tesseract.recognize !== "function") {
    $("ocrStatus").textContent = "OCR library did not load. Check your internet connection and refresh.";
    return;
  }

  $("ocrBtn").disabled = true;
  $("useOcrTextBtn").disabled = true;
  $("ocrStatus").textContent = "Preparing OCR...";

  try {
    const result = await window.Tesseract.recognize(file, "eng", {
      logger: message => {
        if (message.status === "recognizing text") {
          $("ocrStatus").textContent =
            `Recognizing text: ${Math.round((message.progress || 0) * 100)}%`;
        } else if (message.status) {
          $("ocrStatus").textContent = `OCR: ${message.status}...`;
        }
      }
    });

    const extracted = (result.data.text || "").trim().slice(0, 10000);
    $("ocrOutput").value = extracted;
    $("ocrStatus").textContent = extracted
      ? `OCR finished. Extracted ${extracted.length} characters. Review the text for errors.`
      : "No text was recognized. Try a clearer image with larger text.";
    $("useOcrTextBtn").disabled = !extracted;
  } catch (error) {
    console.error("OCR error:", error);
    $("ocrStatus").textContent = "OCR failed. Try a clearer image or refresh the page and retry.";
  } finally {
    $("ocrBtn").disabled = false;
  }
});

$("useOcrTextBtn").addEventListener("click", () => {
  input.value = $("ocrOutput").value;
  input.dispatchEvent(new Event("input"));
  runAnalysis(input.value);
});

$("themeToggle").addEventListener("click", () => {
  const isLight = document.body.classList.toggle("light");
  $("themeToggle").textContent = isLight ? "☾" : "☼";
  $("themeToggle").setAttribute("aria-label", isLight ? "Switch to dark theme" : "Switch to light theme");
});

window.addEventListener("beforeunload", () => {
  if (selectedImageUrl) URL.revokeObjectURL(selectedImageUrl);
});
