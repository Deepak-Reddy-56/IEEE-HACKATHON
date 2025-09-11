// === Config ===
const MODEL_ID = "gemini-2.5-flash-preview-05-20";
const BASE_URL = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL_ID}:generateContent`;

// === DOM Refs ===
const analyzeButton = document.getElementById("analyze-button");
const replyButton = document.getElementById("reply-button");
const clearButton = document.getElementById("clear-button");
const messageInput = document.getElementById("message-input");
const resultContainer = document.getElementById("result-container");
const loadingIndicator = document.getElementById("loading-indicator");
const analysisResult = document.getElementById("analysis-result");
const riskFill = document.getElementById("risk-fill");
const riskLabel = document.getElementById("risk-label");
const linksPanel = document.getElementById("links-panel");
const linksList = document.getElementById("links-list");
const liveScanToggle = document.getElementById("live-scan-toggle");
const charCount = document.getElementById("char-count");

const settingsBtn = document.getElementById("settings-btn");
const settingsModal = document.getElementById("settings-modal");
const closeSettings = document.getElementById("close-settings");
const saveSettings = document.getElementById("save-settings");
const apiKeyInput = document.getElementById("api-key");
const sampleBtn = document.getElementById("sample-btn");

const consentBtn = document.getElementById("consent-button");
const consentModal = document.getElementById("consent-modal");
const maskedPreview = document.getElementById("masked-preview");
const consentCheckbox = document.getElementById("consent-checkbox");
const sendConsentBtn = document.getElementById("send-consent-btn");
const cancelConsent = document.getElementById("cancel-consent");
const closeConsent = document.getElementById("close-consent-btn");

// === Local Storage Keys ===
const LS_KEY = "PHISHING_SHIELD_GEMINI_KEY";

// === Utility: Safe node creation to avoid XSS ===
function createEl(tag, opts = {}) {
  const el = document.createElement(tag);
  if (opts.className) el.className = opts.className;
  if (opts.text != null) el.textContent = opts.text; // never innerHTML for user/model text
  if (opts.attrs)
    for (const [k, v] of Object.entries(opts.attrs)) el.setAttribute(k, v);
  return el;
}

// === Utility: Exponential Backoff Fetch ===
async function fetchWithBackoff(url, options, retries = 3, delay = 1000) {
  try {
    const res = await fetch(url, options);
    if (res.status === 429 && retries > 0) {
      await new Promise((r) => setTimeout(r, delay));
      return fetchWithBackoff(url, options, retries - 1, delay * 2);
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res;
  } catch (err) {
    if (retries > 0) {
      await new Promise((r) => setTimeout(r, delay));
      return fetchWithBackoff(url, options, retries - 1, delay * 2);
    }
    throw err;
  }
}

// === Heuristics (runs locally, in real time) ===
const WORDS_URGENCY = [
  "urgent","immediately","now","asap","act now","final notice","last warning","suspend","suspended","verify now","limited time","expires","deadline",
];
const WORDS_CREDS = [
  "password","passcode","otp","one-time","one time","2fa","verification code","login","log in","sign in","credentials","account details",
];
const WORDS_MONEY = [
  "gift card","crypto","bitcoin","wire","bank transfer","western union","payment","invoice","refund","prize","lottery","cash","paypal","phonePe","Gpay","Free gift","prize winner","you've won","exclusive offer","new job opportunity","you won't believe","secret","see who viewed your profile",
];
const SUSPICIOUS_TLDS = ["zip","mov","gq","tk","ml","cf","ga","top","virus","malware","ly"];
const BRAND_KEYWORDS = ["microsoft1","google1","apple0","paypal-1","amazon01","bank","netflix2","netmirror","bitcoin"];

// quick & cheap distance for lookalike detection (Levenshtein-lite)
function editDistance(a, b) {
  a = a.toLowerCase();
  b = b.toLowerCase();
  const dp = Array.from({ length: a.length + 1 }, () =>
    Array(b.length + 1).fill(0)
  );
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }
  return dp[a.length][b.length];
}

/**
 * extractUrls
 * returns array of { raw, normalized, hasScheme }
 * - raw: the original matched fragment from text (friendly display)
 * - normalized: a URL string with http:// prefixed if no scheme present (safe for URL parsing)
 * - hasScheme: whether the original user text included an explicit http/https scheme
 */
function extractUrls(text) {
  const regex =
    /\b((?:https?:\/\/)?(?:[\w-]+\.)+[a-z]{2,}(?:\/[^\s]*)?|\bhttps?:\/\/\S+)/gi;
  const matches = text.match(regex) || [];
  return matches.map((u) => {
    const hasScheme = /^https?:\/\//i.test(u);
    // normalize for parsing (but keep hasScheme)
    const normalized = hasScheme ? u : (u.startsWith("http://") || u.startsWith("https://") ? u : "http://" + u);
    return { raw: u, normalized, hasScheme };
  });
}

/**
 * analyzeLinks
 * Accepts array of objects from extractUrls and returns findings that include host, tld, flags
 */
function analyzeLinks(urlObjs) {
  const findings = [];
  for (const obj of urlObjs) {
    const rawToShow = obj.raw;
    try {
      const u = new URL(obj.normalized);
      const host = u.hostname;
      const parts = host.split(".");
      const tld = parts[parts.length - 1] || "";
      const isIP = /^[0-9.]+$/.test(host);
      const tooManyDots = (host.match(/\./g) || []).length >= 3;
      const hasAt = obj.raw.includes("@");

      const tldSuspicious = SUSPICIOUS_TLDS.includes(tld.toLowerCase());
      const lookalikes = BRAND_KEYWORDS.map((b) => ({
        brand: b,
        dist: editDistance(host.replace(/^www\./, ""), b),
      })).filter((x) => x.dist > 0 && x.dist <= 2);

      const flags = [];
      if (isIP) flags.push("IP-only host");
      if (tooManyDots) flags.push("Many dots in hostname");
      if (hasAt) flags.push("'@' present in URL");
      if (tldSuspicious) flags.push(`Suspicious TLD .${tld}`);
      if (lookalikes.length) flags.push("Possible brand lookalike");

      findings.push({ url: rawToShow, normalized: obj.normalized, host, tld, flags });
    } catch (_) {
      findings.push({ url: rawToShow, host: "-", tld: "-", flags: ["Malformed URL"] });
    }
  }
  return findings;
}

function scoreHeuristics(text) {
  const lc = text.toLowerCase();
  const signals = [];

  // Count matches
  const urgCount = WORDS_URGENCY.filter(w => lc.includes(w)).length;
  const credCount = WORDS_CREDS.filter(w => lc.includes(w)).length;
  const moneyCount = WORDS_MONEY.filter(w => lc.includes(w)).length;

  const lines = text.split(/\r?\n/);
  const shouty = lines.filter(l => l.trim().length >= 6 && l === l.toUpperCase()).length;
  const excls = (text.match(/!/g) || []).length;

  const urlObjs = extractUrls(text);
  const linkFindings = analyzeLinks(urlObjs);

  // Score components (normalized and safer weights)
  // Penalize only when explicit http scheme is present in the original text (hasScheme)
  const httpLinks = urlObjs.filter(u => u.hasScheme && u.normalized.startsWith("http://")).length;
  const httpLinkScore = Math.min(httpLinks * 20, 40); // smaller penalty for explicitly insecure http links

  const urgencyScore = Math.min(urgCount * 12, 36);       // reduce per-cue weight
  const credsScore = Math.min(credCount * 18, 36);        // reduce per-cue weight
  const moneyScore = Math.min(moneyCount * 10, 30);       // reduce per-cue weight
  const brandScore = linkFindings.some(f => f.flags.some(fl => fl.toLowerCase().includes("brand"))) ? 20 : 0;
  const shoutScore = Math.min(shouty * 12, 18);
  const exclScore = Math.min(excls * 4, 12);
  const linkScore = Math.min(urlObjs.length * 5, 25);

  // suspicious TLDs in actual links (not just text)
  const suspiciousLinks = linkFindings.filter(f => f.flags.some(flag => /^Suspicious TLD/i.test(flag))).length;
  const susscore = Math.min(suspiciousLinks * 30, 60);

  let linkFlagsScore = 0;
  for (const f of linkFindings) linkFlagsScore += f.flags.length * 2;
  linkFlagsScore = Math.min(linkFlagsScore, 12);         // cap

  const rawScore = httpLinkScore + urgencyScore + credsScore + moneyScore + brandScore + shoutScore + exclScore + linkScore + linkFlagsScore + susscore;

  // clamp to 0-100 and round
  const score = Math.max(0, Math.min(100, Math.round(rawScore)));

  // Determine level
  let level = "Low";
  if (score >= 70) level = "High";
  else if (score >= 35) level = "Medium";

  // Add signals for display
  if (urgCount) signals.push({ type: "Urgency", weight: urgencyScore, detail: `Found ${urgCount} urgency cue(s)` });
  if (credCount) signals.push({ type: "Credentials Request", weight: credsScore, detail: `Mentions of credentials/OTP: ${credCount}` });
  if (moneyCount) signals.push({ type: "Financial Ask", weight: moneyScore, detail: `Payment-related terms: ${moneyCount}` });
  if (brandScore) signals.push({ type: "Brand Impersonation", weight: brandScore, detail: `Possible brand lookalike detected in links` });
  if (shouty) signals.push({ type: "Shouting", weight: shoutScore, detail: `${shouty} line(s) in ALL CAPS` });
  if (excls >= 3) signals.push({ type: "Excessive Punctuation", weight: exclScore, detail: `${excls} exclamation marks` });
  if (urlObjs.length) signals.push({ type: "Links Present", weight: linkScore, detail: `${urlObjs.length} link(s) detected` });
  if (linkFlagsScore) signals.push({ type: "Link Flags", weight: linkFlagsScore, detail: "Suspicious link characteristics present" });

  // return normalized values: urls array is user-facing raw matches
  return { score, level, signals, urls: urlObjs.map(u=>u.raw), linkFindings };
}


// === UI: Risk Meter & Labels ===
function setRisk(score, level) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  riskFill.style.width = `${clamped}%`;
  riskLabel.textContent = `${level} (${clamped})`;
  riskLabel.className = "text-sm px-2 py-1 rounded-lg";
  // reset background classes by reassigning className above then adding one
  if (level === "High") riskLabel.classList.add("bg-red-600/30");
  else if (level === "Medium") riskLabel.classList.add("bg-amber-600/30");
  else if (level === "Low") riskLabel.classList.add("bg-green-600/30");
  else riskLabel.classList.add("bg-slate-800");
}

// === Gemini Calls (optional) ===
function getApiKey() {
  // Prefer local storage, then settings input, then (fallback) the embedded demo key.
  const stored = localStorage.getItem(LS_KEY);
  if (stored && stored.trim()) return stored.trim();
  const inputVal = apiKeyInput?.value?.trim();
  if (inputVal) return inputVal;
  // NOTE: demo fallback key (kept for backward compatibility)
  return "AIzaSyDProgkS5MM96wGe-sUJ5z5f0b0HE95ayY";
}

async function analyzeWithGemini(message) {
  const apiKey = getApiKey();
  if (!apiKey) return null; // no AI if key not set

  const systemPrompt =
    "You are a cybersecurity assistant. The user has received a suspicious or potentially phishing message. Generate a **short, polite, and safe reply** that:- Identifies the suspicious link(s) from the message. Warns the user NOT to click them. Provides the **official website link** of the organization if identifiable (e.g., if scam link is 'secure-paypa1.com', provide 'https://www.paypal.com') - If no official site can be determined, say Please verify only through the official website you normally use - Do not include any personal details, OTPs, or sensitive data.- Keep the tone professional and cautious.- Limit reply to 4-5 sentences. Respond ONLY in strict JSON with keys riskLevel and reasoning.";

  const payload = {
    systemInstruction: { role: "system", parts: [{ text: systemPrompt }] },
    contents: [
      {
        role: "user",
        parts: [
          {
            text:
              "Analyze this message for phishing risk. " +
              "Return JSON as {\"riskLevel\":\"High|Medium|Low\",\"reasoning\":\"1-3 concise sentences\"}.\n\n" +
              "Message:\n" + message,
          },
        ],
      },
    ],
    generationConfig: {
      temperature: 0.2,
      responseMimeType: "application/json",
    },
  };

  const res = await fetchWithBackoff(
    `${BASE_URL}?key=${encodeURIComponent(apiKey)}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }
  );

  const data = await res.json();
  const jsonText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!jsonText) return null;

  try {
    const parsed = JSON.parse(jsonText);
    if (typeof parsed?.riskLevel === "string" && typeof parsed?.reasoning === "string") {
      return { riskLevel: parsed.riskLevel, reasoning: parsed.reasoning };
    }
  } catch (_) {
    // fall through
  }
  return null;
}

async function generateSafeReply(message) {
  const apiKey = getApiKey();
  const fallback =
    "Thanks for reaching out. I can’t verify this request or the link provided, so I won’t be sharing any personal information. If this is legitimate, please contact me through an official channel I can independently verify.";

  if (!apiKey) return fallback;

  const payload = {
    contents: [
      {
        role: "user",
        parts: [
          {
            text:
`You are a cybersecurity assistant.

Return STRICT JSON with these keys:
- risk level: "Low" | "Medium" | "High"
- analysis: short explanation (1–3 sentences)
- safe reply: a single short paragraph I can send back

Input:
"${message}"`,
          },
        ],
      },
    ],
    generationConfig: {
      temperature: 0.3,
      responseMimeType: "application/json",
    },
  };

  const res = await fetchWithBackoff(
    `${BASE_URL}?key=${encodeURIComponent(apiKey)}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }
  );

  const data = await res.json();
  const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!text) return fallback;

  try {
    const obj = JSON.parse(text);
    const reply = obj?.["safe reply"];
    if (reply && typeof reply === "string") return reply;
  } catch (_) {}
  return fallback;
}

// === Masking: Protect user PII before sending to AI ===
function maskSensitiveData(text) {
  let masked = String(text);

  const report = { emails: 0, phones: 0, pins: 0, accounts: 0, cards: 0, addresses: 0, names: 0 };

  // 1) Emails
  const emailRegex = /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
  masked = masked.replace(emailRegex, (m) => {
    report.emails++;
    return "[REDACTED EMAIL]";
  });

  // 2) PIN (explicit)
  const pinRegex = /\b(pin|PIN)\s*[:\-]?\s*(\d{4,6})\b/g;
  masked = masked.replace(pinRegex, (m) => {
    report.pins++;
    return "[REDACTED PIN]";
  });

  // 3) Credit-card like sequences (13-19 digits, allow spaces/dashes)
  const cardRegex = /(?<!\d)(?:\d[ \-]*){13,19}(?!\d)/g;
  masked = masked.replace(cardRegex, (m) => {
    report.cards++;
    return "[REDACTED CARD]";
  });

  // 4) Phone numbers (various formats, keep loose but practical)
  const phoneRegex = /(\+?\d{1,3}[-.\s(]*\d{2,4}[-.\s)]*\d{2,4}[-.\s]*\d{2,4})/g;
  masked = masked.replace(phoneRegex, (m) => {
    // avoid masking short digit groups only (e.g. 2-digit years)
    const digitsOnly = m.replace(/\D/g, "");
    if (digitsOnly.length < 7) return m; // probably not a phone
    report.phones++;
    return "[REDACTED PHONE]";
  });

  // 5) Account numbers (long digit sequences 8+ digits not already caught)
  const accountRegex = /(?<!\d)(\d{8,20})(?!\d)/g;
  masked = masked.replace(accountRegex, (m) => {
    report.accounts++;
    return "[REDACTED ACCOUNT]";
  });

  // 6) Addresses (number + street or keywords)
  // Replace the old addressRegex with this one:
const addressRegex = /\b\d{1,5}[A-Za-z]?\s+(?:[A-Za-z0-9#]+\s?){1,6}(Street|St\.|Road|Rd\.|Avenue|Ave\.|Boulevard|Blvd\.|Lane|Ln\.|Drive|Dr\.|Suite|Ste\.|Apt|Apartment|Floor|Fl)\b[^,\n]*(?:,\s*[A-Za-z\s]+)?/gi;

  masked = masked.replace(addressRegex, (m) => {
    report.addresses++;
    return "[REDACTED ADDRESS]";
  });

  // 7) "Name: John Doe" style explicit labels
  const nameLabelRegex = /\b(Name|Full Name|Your Name)\s*[:\-]\s*([A-Z][a-z]+(?:\s[A-Z][a-z]+)*)/g;
  masked = masked.replace(nameLabelRegex, (m, p1) => {
    report.names++;
    return `${p1}: [REDACTED NAME]`;
  });

  // 8) Greetings like "Dear John" or "Hi John"
  const greetRegex = /(^|\n)(\s*(Dear|Hi|Hello|Hey)\s+)([A-Z][a-z]+(?:\s[A-Z][a-z]+)?)/g;
  masked = masked.replace(greetRegex, (m, p1, p2) => {
    report.names++;
    return `${p1}${p2}[REDACTED NAME]`;
  });

  return { masked, report };
}

// === Rendering ===
function renderLinks(findings) {
  linksList.innerHTML = "";
  if (!findings.length) {
    linksPanel.classList.add("hidden");
    return;
  }
  linksPanel.classList.remove("hidden");
  for (const f of findings) {
    const li = createEl("li", {
      className: "p-3 rounded-lg bg-slate-900 border border-slate-700",
    });

    const top = createEl("div", {
      className: "flex items-center justify-between gap-3",
    });
    const urlSpan = createEl("span", { className: "truncate", text: f.url });
    const open = createEl("a", {
      className: "y2k-button-secondary text-xs",
      attrs: { href: f.normalized || f.url, target: "_blank", rel: "noopener noreferrer" },
      text: "Open (cautiously)",
    });
    top.appendChild(urlSpan);
    top.appendChild(open);

    const meta = createEl("div", { className: "mt-2 text-xs text-slate-300" });
    meta.textContent = `Host: ${f.host}   TLD: ${f.tld}`;

    const flags = createEl("div", { className: "mt-2 flex flex-wrap gap-2" });
    if (f.flags.length) {
      for (const flag of f.flags) {
        const chip = createEl("span", {
          className:
            "px-2 py-1 rounded-full bg-red-600/20 text-red-200 text-xs",
          text: flag,
        });
        flags.appendChild(chip);
      }
    } else {
      const ok = createEl("span", {
        className:
          "px-2 py-1 rounded-full bg-green-600/20 text-green-200 text-xs",
        text: "No obvious flags",
      });
      flags.appendChild(ok);
    }

    li.appendChild(top);
    li.appendChild(meta);
    li.appendChild(flags);
    linksList.appendChild(li);
  }
}

function renderAnalysisCard({ finalLevel, finalReason, heur, ai, note }) {
  analysisResult.className = "y2k-result"; // reset
  if (finalLevel === "High") analysisResult.classList.add("phishing");
  else if (finalLevel === "Medium") analysisResult.classList.add("medium");
  else if (finalLevel === "Low") analysisResult.classList.add("safe");
  else analysisResult.classList.add("reply");

  const wrapper = createEl("div");

  const title = createEl("p", { className: "text-2xl font-bold mb-1" });
  title.textContent =
    finalLevel === "High" ? "🚨 HIGH RISK"
    : finalLevel === "Medium" ? "⚠️ MEDIUM RISK"
    : finalLevel === "Low" ? "✅ Looks Safe"
    : "ℹ️ Result";

  const reason = createEl("p", { className: "mt-1 text-base" });
  reason.textContent = finalReason;

  wrapper.appendChild(title);
  wrapper.appendChild(reason);

  const hTitle = createEl("p", {
    className: "mt-4 font-semibold",
    text: "Key Signals (local heuristics)",
  });
  wrapper.appendChild(hTitle);

  if (heur.signals.length) {
    const ul = createEl("ul", {
      className: "list-disc ml-6 space-y-1 text-sm",
    });
    for (const s of heur.signals) {
      const li = createEl("li");
      li.textContent = `${s.type}: ${s.detail}`;
      ul.appendChild(li);
    }
    wrapper.appendChild(ul);
  } else {
    wrapper.appendChild(
      createEl("p", { className: "text-sm", text: "No strong local phishing signals." })
    );
  }

  if (ai) {
    const sep = createEl("hr", { attrs: { role: "presentation" } });
    const aiTitle = createEl("p", {
      className: "mt-4 font-semibold",
      text: "AI Assessment",
    });
    const aiP = createEl("p", { className: "text-sm" });
    aiP.textContent = `AI Risk: ${ai.riskLevel} — ${ai.reasoning}`;
    wrapper.appendChild(sep);
    wrapper.appendChild(aiTitle);
    wrapper.appendChild(aiP);
  }

  if (note) {
    const noteEl = createEl("p", { className: "mt-4 text-xs italic", text: note });
    wrapper.appendChild(noteEl);
  }

  const tip = createEl("p", { className: "mt-4 text-xs font-semibold" });
  tip.textContent =
    finalLevel === "High" || finalLevel === "Medium"
      ? "Do not click links or share information until independently verified."
      : "Stay cautious and inspect links before clicking.";

  wrapper.appendChild(tip);

  analysisResult.innerHTML = "";
  analysisResult.appendChild(wrapper);
}

// === Pipeline ===
async function runAnalysis() {
  const text = messageInput.value.trim();
  if (!text) return;

  resultContainer.classList.remove("hidden");
  loadingIndicator.style.display = "flex";
  analysisResult.innerHTML = "";
  analysisResult.className = "y2k-result";

  const heur = scoreHeuristics(text);
  setRisk(heur.score, heur.level);
  renderLinks(heur.linkFindings);

  let ai = null;
  try {
    ai = await analyzeWithGemini(text);
  } catch {
    // ignore; heuristics still shown
  }

  loadingIndicator.style.display = "none";

  let finalLevel = heur.level;
  let finalReason = `Local score ${heur.score}/100.`;
  if (ai) {
    const order = { Low: 0, Medium: 1, High: 2 };
    finalLevel = order[ai.riskLevel] > order[heur.level] ? ai.riskLevel : heur.level;
    finalReason = `Local score ${heur.score}/100. ${ai.reasoning}`;
  }

  renderAnalysisCard({ finalLevel, finalReason, heur, ai });
}

// === Events ===
analyzeButton.addEventListener("click", () => {
  const text = messageInput.value.trim();
  if (!text) {
    alert("Please paste a message to analyze.");
    return;
  }
  const { masked } = maskSensitiveData(text);
  maskedPreview.textContent = masked || "—";
  consentCheckbox.checked = false;
  sendConsentBtn.disabled = true;
  consentModal.showModal();
});


replyButton.addEventListener("click", async () => {
  const text = messageInput.value.trim();
  if (!text) return;

  resultContainer.classList.remove("hidden");
  loadingIndicator.style.display = "flex";
  analysisResult.innerHTML = "";
  analysisResult.className = "y2k-result";

  try {
    const replyText = await generateSafeReply(text);
    loadingIndicator.style.display = "none";

    analysisResult.classList.add("reply");
    const title = createEl("p", {
      className: "text-2xl font-bold mb-2",
      text: "✨ Suggested Safe Reply ✨",
    });
    const body = createEl("p", { className: "text-base text-slate-900" });
    body.textContent = replyText;

    const copyBtn = createEl("button", {
      className: "y2k-button-secondary mt-4",
      text: "Copy",
    });
    copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(replyText);
        copyBtn.textContent = "Copied!";
      } catch {
        copyBtn.textContent = "Copy failed";
      }
      setTimeout(() => (copyBtn.textContent = "Copy"), 1200);
    });

    analysisResult.innerHTML = "";
    analysisResult.appendChild(title);
    analysisResult.appendChild(body);
    analysisResult.appendChild(copyBtn);
    analysisResult.style.display = "block";
  } catch (e) {
    loadingIndicator.style.display = "none";
    analysisResult.classList.add("phishing");
    analysisResult.textContent = "Error generating reply.";
  }
});

clearButton.addEventListener("click", () => {
  messageInput.value = "";
  charCount.textContent = "0 characters";
  setRisk(0, "Unknown");
  linksPanel.classList.add("hidden");
  resultContainer.classList.add("hidden");
  analysisResult.innerHTML = "";
});

messageInput.addEventListener("input", () => {
  const text = messageInput.value;
  charCount.textContent = `${text.length} character${text.length === 1 ? "" : "s"}`;
  if (!liveScanToggle.checked) return;

  if (!text.trim()) {
    setRisk(0, "Unknown");
    linksPanel.classList.add("hidden");
    resultContainer.classList.add("hidden");
    return;
  }

  const heur = scoreHeuristics(text);
  setRisk(heur.score, heur.level);
  renderLinks(heur.linkFindings);

  resultContainer.classList.remove("hidden");
  loadingIndicator.style.display = "none";
  renderAnalysisCard({
    finalLevel: heur.level,
    finalReason: `Local score ${heur.score}/100.`,
    heur,
    ai: null,
  });
});

// Settings modal
settingsBtn.addEventListener("click", () => {
  apiKeyInput.value = localStorage.getItem(LS_KEY) || "AIzaSyDProgkS5MM96wGe-sUJ5z5f0b0HE95ayY";
  settingsModal.showModal();
});
closeSettings.addEventListener("click", (e) => {
  e.preventDefault();
  settingsModal.close();
});
saveSettings.addEventListener("click", (e) => {
  e.preventDefault();
  const k = apiKeyInput.value.trim();
  if (k) localStorage.setItem(LS_KEY, k);
  else localStorage.removeItem(LS_KEY);
  settingsModal.close();
});

// Sample
sampleBtn.addEventListener("click", async () => {
  const sample = `FINAL NOTICE: Your account will be SUSPENDED in 24 HOURS.
Click https://secure-support-paypa1.com/login to verify your password and 2FA NOW.
Failure to act will result in permanent closure and loss of funds.`;
  messageInput.value = sample;
  messageInput.dispatchEvent(new Event("input"));
});

// --- Consent workflow: mask then send to Gemini ---
consentBtn.addEventListener("click", () => {
  const text = messageInput.value.trim();
  if (!text) {
    alert("Please paste a message to send.");
    return;
  }
  const { masked } = maskSensitiveData(text);
  maskedPreview.textContent = masked || "—";
  consentCheckbox.checked = false;
  sendConsentBtn.disabled = true;
  consentModal.showModal();
});

consentCheckbox.addEventListener("change", () => {
  sendConsentBtn.disabled = !consentCheckbox.checked;
});

cancelConsent.addEventListener("click", (e) => {
  e.preventDefault();
  consentModal.close();
});
closeConsent.addEventListener("click", (e) => {
  e.preventDefault();
  consentModal.close();
});

sendConsentBtn.addEventListener("click", async (e) => {
  e.preventDefault();
  const text = messageInput.value.trim();
  if (!text) return;

  const { masked, report } = maskSensitiveData(text);

  // show loading + call
  resultContainer.classList.remove("hidden");
  loadingIndicator.style.display = "flex";
  analysisResult.innerHTML = "";
  analysisResult.className = "y2k-result";

  try {
    const ai = await analyzeWithGemini(masked);
    loadingIndicator.style.display = "none";
    consentModal.close();

    // build a small note about masking counts
    let note = `Masked content sent. Redactions: `;
    const parts = [];
    for (const k of Object.keys(report)) {
      if (report[k]) parts.push(`${k}: ${report[k]}`);
    }
    if (parts.length === 0) note += "none detected.";
    else note += parts.join(", ") + ".";

    // combine heuristics for display
    const heur = scoreHeuristics(text);
    let finalLevel = heur.level;
    let finalReason = `Local score ${heur.score}/100.`;
    if (ai) {
      const order = { Low: 0, Medium: 1, High: 2 };
      finalLevel = order[ai.riskLevel] > order[heur.level] ? ai.riskLevel : heur.level;
      finalReason = `Local score ${heur.score}/100. ${ai.reasoning}`;
    }

    renderAnalysisCard({ finalLevel, finalReason, heur, ai, note });
  } catch (err) {
    loadingIndicator.style.display = "none";
    analysisResult.classList.add("phishing");
    analysisResult.textContent = "Error sending masked content to Gemini.";
  }
});
