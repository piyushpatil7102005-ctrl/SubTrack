/* ##################################################################
   SOURCE: file.js (auth + app logic + theme)
   ################################################################## */
/* =====================================================================
   Auth — local accounts (no Firebase) + email OTP verification
   ---------------------------------------------------------------------
   Accounts are stored in this browser (passwords are salted + hashed).
   A 6-digit one-time
   code is emailed (via EmailJS) the moment someone signs up, or logs in
   from a browser that hasn't been verified yet; they must type it in
   before they get into the app. Subscription data is kept in this
   browser's localStorage, in a separate space per email address.
   ===================================================================== */

/* ------------------------- Local accounts (replaces Firebase) ------------------------- */
// Accounts and the signed-in session live in this browser's localStorage.
// No server, no API keys. (Fine for a mini project / demo; a real production
// app should use a backend such as Firebase or Supabase.)
const ACCOUNTS_KEY = "subtracker.accounts.v1";
const SESSION_KEY = "subtracker.session.v1";

async function hashPassword(password, salt) {
  if (window.crypto && crypto.subtle) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"],
    );
    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: enc.encode(salt),
        iterations: 100000,
        hash: "SHA-256",
      },
      key,
      256,
    );
    return [...new Uint8Array(bits)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
  return `plain:${salt}:${password}`;
}

const localAuth = {
  currentUser: null,
  _listeners: [],
  _accounts() {
    try {
      return JSON.parse(localStorage.getItem(ACCOUNTS_KEY)) || {};
    } catch {
      return {};
    }
  },
  _saveAccounts(a) {
    localStorage.setItem(ACCOUNTS_KEY, JSON.stringify(a));
  },
  // NEW: true if an account with this email already exists in this browser.
  emailExists(email) {
    return !!this._accounts()[email];
  },
  _setUser(email, name) {
    this.currentUser = email ? { email, displayName: name || "" } : null;
    if (email) localStorage.setItem(SESSION_KEY, email);
    else localStorage.removeItem(SESSION_KEY);
    this._listeners.forEach((cb) => cb(this.currentUser));
  },
  onAuthStateChanged(cb) {
    this._listeners.push(cb);
    const email = localStorage.getItem(SESSION_KEY);
    const acc = email && this._accounts()[email];
    this.currentUser = acc ? { email, displayName: acc.name || "" } : null;
    cb(this.currentUser);
  },
  async signUp(email, password, name) {
    const accounts = this._accounts();
    if (accounts[email]) throw { code: "auth/email-already-in-use" };
    const salt = crypto.randomUUID
      ? crypto.randomUUID()
      : String(Math.random()).slice(2);
    accounts[email] = { name, salt, hash: await hashPassword(password, salt) };
    this._saveAccounts(accounts);
    this._setUser(email, name);
  },
  async signIn(email, password) {
    const acc = this._accounts()[email];
    if (!acc || (await hashPassword(password, acc.salt)) !== acc.hash)
      throw { code: "auth/invalid-credential" };
    this._setUser(email, acc.name);
  },
  signOut() {
    this._setUser(null);
  },
};

// Per-user data keys, e.g. subtracker.subscriptions.v1::alice@gmail.com
const SUBS_KEY_BASE = "subtracker.subscriptions.v1";
const AUTOPAY_KEY_BASE = "subtracker.autopayLastRun.v1";
const REMINDERS_KEY_BASE = "subtracker.remindersSent.v1";

/* ---------------------------- Email OTP settings ---------------------------- */
// Codes are emailed through EmailJS (https://www.emailjs.com).
// Template: "To Email" = {{to_email}}; body uses {{to_name}}, {{otp_code}},
// {{expires_in}}, {{app_name}}. Paste your three EmailJS values here.
const EMAILJS_CONFIG = {
  serviceId: "service_dbhgo55",
  templateId: "template_yh3b5ab", // OTP template
  publicKey: "kieuVAf2aiC8iOQrG",
  // A SECOND EmailJS template used for "subscription ending" reminders.
  reminderTemplateId: "template_zjtj4im",
};
const OTP_LENGTH = 6;
const OTP_TTL_MS = 10 * 60 * 1000; // code valid for 10 minutes
const OTP_RESEND_COOLDOWN_MS = 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;
// TESTING ONLY: shows the code on screen instead of emailing it.
// Keep false so codes go to the user's real inbox via EmailJS.
const DEMO_SHOW_CODE_ON_SCREEN = false;
const VERIFIED_KEY = "subtracker.otpVerified.v1"; // emails verified in THIS browser

/* -------------------------- Email reminder settings -------------------------- */
// Send a reminder when a subscription ends/renews within this many days.
const REMINDER_DAYS_BEFORE = 3;
// Also remind about non-autopay subscriptions that ended up to this many days ago.
const REMINDER_OVERDUE_DAYS = 7;
// While the tab stays open, re-check this often.
const REMINDER_CHECK_INTERVAL_MS = 60 * 60 * 1000; // every hour

let currentEmail = null; // set only for a signed-in AND email-verified user

function getSession() {
  return currentEmail;
}

function userScopedKey(base) {
  return currentEmail ? `${base}::${currentEmail}` : null;
}

const authEl = {
  screen: document.getElementById("authScreen"),
  appRoot: document.getElementById("appRoot"),

  loginTabBtn: document.getElementById("loginTabBtn"),
  signupTabBtn: document.getElementById("signupTabBtn"),
  loginForm: document.getElementById("loginForm"),
  signupForm: document.getElementById("signupForm"),
  loginError: document.getElementById("loginError"),
  signupError: document.getElementById("signupError"),

  loginEmail: document.getElementById("loginEmail"),
  loginPassword: document.getElementById("loginPassword"),
  signupName: document.getElementById("signupName"),
  signupEmail: document.getElementById("signupEmail"),
  signupPassword: document.getElementById("signupPassword"),

  currentUserLabel: document.getElementById("currentUserLabel"),
  logoutBtn: document.getElementById("logoutBtn"),
};

const auth = localAuth;

/* ---------------------------- Email validation ---------------------------- */
// A browser-only app can prove an email's *domain* is real (it has mail
// servers) but cannot prove a specific mailbox exists — only sending a
// confirmation code/link can do that, which needs a backend or an email
// service. These checks block the obvious fakes: bad format, throwaway
// domains, typo'd domains, and domains that don't exist / don't accept mail.

const EMAIL_REGEX =
  /^[a-z0-9._%+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,})$/i;

const DISPOSABLE_DOMAINS = new Set([
  "mailinator.com", "10minutemail.com", "10minutemail.net",
  "guerrillamail.com", "guerrillamail.net", "guerrillamail.org",
  "sharklasers.com", "grr.la", "tempmail.com", "temp-mail.org",
  "temp-mail.io", "tempmailo.com", "throwawaymail.com", "yopmail.com",
  "yopmail.net", "trashmail.com", "getnada.com", "nada.email",
  "dispostable.com", "maildrop.cc", "fakeinbox.com", "mailnesia.com",
  "mintemail.com", "moakt.com", "emailondeck.com", "mohmal.com",
  "burnermail.io", "discard.email", "spamgourmet.com", "mytemp.email",
  "tmpmail.org", "tmpmail.net", "inboxkitten.com", "mail.tm",
  "example.com", "example.org", "example.net", "test.com", "test.test",
  "invalid.com", "fake.com", "fakemail.com", "noemail.com",
  "email.com.invalid",
]);

// Common typos -> the domain the person probably meant.
const DOMAIN_TYPOS = {
  "gmial.com": "gmail.com",
  "gmai.com": "gmail.com",
  "gmail.co": "gmail.com",
  "gmail.con": "gmail.com",
  "gamil.com": "gmail.com",
  "gmal.com": "gmail.com",
  "gnail.com": "gmail.com",
  "gmaill.com": "gmail.com",
  "gmail.cm": "gmail.com",
  "yaho.com": "yahoo.com",
  "yahooo.com": "yahoo.com",
  "yahoo.co": "yahoo.com",
  "yahoo.con": "yahoo.com",
  "hotmial.com": "hotmail.com",
  "hotmail.con": "hotmail.com",
  "outlok.com": "outlook.com",
  "outlook.con": "outlook.com",
  "iclod.com": "icloud.com",
  "icloud.con": "icloud.com",
};

async function dnsHasRecord(domain, type) {
  const providers = [
    `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`,
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`,
  ];
  let lastError = null;
  for (const url of providers) {
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 6000);
      const res = await fetch(url, {
        headers: { accept: "application/dns-json" },
        signal: ctrl.signal,
      });
      clearTimeout(timer);
      if (!res.ok) throw new Error(`DNS lookup failed (${res.status})`);
      const data = await res.json();
      if (data.Status === 3) return false; // NXDOMAIN — domain doesn't exist
      const answers = (data.Answer || []).filter(
        (a) => a.type === (type === "MX" ? 15 : 1),
      );
      if (type === "MX") {
        // "0 ." is a "null MX" — the domain explicitly accepts no email.
        return answers.some((a) => !/^0\s+\.?$/.test(String(a.data).trim()));
      }
      return answers.length > 0;
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError || new Error("DNS lookup failed");
}

// Returns { ok: true } or { ok: false, message }.
async function validateEmailForSignup(email) {
  const m = email.match(EMAIL_REGEX);
  if (!m || email.includes("..")) {
    return { ok: false, message: "Please enter a valid email address." };
  }
  const domain = m[1].toLowerCase();

  if (DOMAIN_TYPOS[domain]) {
    return {
      ok: false,
      message: `Did you mean ${email.split("@")[0]}@${DOMAIN_TYPOS[domain]}?`,
    };
  }
  if (DISPOSABLE_DOMAINS.has(domain)) {
    return {
      ok: false,
      message:
        "Temporary or placeholder email addresses aren't allowed. Use your real email.",
    };
  }

  try {
    const hasMx = await dnsHasRecord(domain, "MX");
    if (hasMx) return { ok: true };
    // Some domains receive mail on their A record with no MX.
    const hasA = await dnsHasRecord(domain, "A");
    if (hasA) return { ok: true };
    return {
      ok: false,
      message: `The domain "${domain}" doesn't exist or can't receive email.`,
    };
  } catch {
    return {
      ok: false,
      message:
        "Couldn't verify that email right now. Check your internet connection and try again.",
    };
  }
}

/* -------------------------------- View toggling -------------------------------- */

function showApp(email, displayName) {
  authEl.screen.classList.add("hidden");
  authEl.appRoot.classList.remove("hidden");
  authEl.currentUserLabel.textContent = displayName
    ? `${displayName} (${email})`
    : email;
}

function showAuth() {
  authEl.appRoot.classList.add("hidden");
  authEl.screen.classList.remove("hidden");
}

function switchTab(tab) {
  const showLogin = tab === "login";
  authEl.loginTabBtn.classList.toggle("active", showLogin);
  authEl.signupTabBtn.classList.toggle("active", !showLogin);
  authEl.loginForm.classList.toggle("hidden", !showLogin);
  authEl.signupForm.classList.toggle("hidden", showLogin);
  authEl.loginError.classList.add("hidden");
  authEl.signupError.classList.add("hidden");
}

function showError(el, message) {
  el.textContent = message;
  el.classList.remove("hidden");
}

function friendlyAuthError(err) {
  const map = {
    "auth/email-already-in-use":
      "An account with that email already exists. Log in instead.",
    "auth/invalid-email": "Please enter a valid email address.",
    "auth/weak-password": "Password must be at least 6 characters.",
    "auth/invalid-credential": "Incorrect email or password.",
    "auth/wrong-password": "Incorrect email or password.",
    "auth/user-not-found": "Incorrect email or password.",
    "auth/user-disabled": "This account has been disabled.",
    "auth/too-many-requests":
      "Too many attempts. Please wait a few minutes and try again.",
    "auth/network-request-failed":
      "Network error. Check your internet connection.",
  };
  return (
    map[err && err.code] ||
    `Something went wrong (${(err && (err.code || err.message)) || "unknown error"}).`
  );
}

/* ------------------------------ Email OTP engine ------------------------------ */

function getVerifiedEmails() {
  try {
    return JSON.parse(localStorage.getItem(VERIFIED_KEY)) || [];
  } catch {
    return [];
  }
}
function isVerifiedHere(email) {
  return getVerifiedEmails().includes(email);
}
function markVerifiedHere(email) {
  const list = getVerifiedEmails();
  if (!list.includes(email)) {
    list.push(email);
    localStorage.setItem(VERIFIED_KEY, JSON.stringify(list));
  }
}
function unmarkVerifiedHere(email) {
  localStorage.setItem(
    VERIFIED_KEY,
    JSON.stringify(getVerifiedEmails().filter((e) => e !== email)),
  );
}

// Pending verification lives only in memory.
let pendingOtp = null;
// { mode: "signup"|"login", name, email, password, otpHash, expiresAt, attempts, lastSentAt }
let otpResendTimer = null;
let otpSendingFor = null;

async function sha256Hex(text) {
  if (window.crypto && crypto.subtle) {
    const buf = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(text),
    );
    return [...new Uint8Array(buf)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
  return `plain:${text}`;
}

function generateOtp() {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return String(arr[0] % 10 ** OTP_LENGTH).padStart(OTP_LENGTH, "0");
}

async function sendOtpEmail(name, email, code) {
  const { serviceId, templateId, publicKey } = EMAILJS_CONFIG;
  if (!serviceId || !templateId || !publicKey) {
    if (DEMO_SHOW_CODE_ON_SCREEN) return { demo: true };
    throw new Error(
      "Email sending isn't set up yet. Add your EmailJS keys at the top of file.js.",
    );
  }
  let res;
  try {
    res = await fetch("https://api.emailjs.com/api/v1.0/email/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        service_id: serviceId,
        template_id: templateId,
        user_id: publicKey,
        template_params: {
          to_email: email,
          to_name: name || email,
          otp_code: code,
          expires_in: `${OTP_TTL_MS / 60000} minutes`,
          app_name: "Subscription Tracker",
        },
      }),
    });
  } catch {
    throw new Error(
      "Couldn't reach the email service. Check your internet connection.",
    );
  }
  if (!res.ok) {
    const detail = (await res.text().catch(() => "")).slice(0, 140);
    const hints = {
      400: 'Check that your Service ID, Template ID and Public Key are correct, and that the template\'s "To Email" is {{to_email}}.',
      401: "Your EmailJS Public Key looks wrong.",
      403: "EmailJS blocked this request. Open the app from localhost or your real site, and check Account → Security → allowed domains.",
      412: "Your email service connection has expired. Reconnect it in EmailJS → Email Services.",
      429: "Too many emails sent. Wait a minute and try again.",
    };
    throw new Error(
      `Couldn't send the verification email. ${hints[res.status] || ""} ${detail}`
        .replace(/\s+/g, " ")
        .trim(),
    );
  }
  return { demo: false };
}

// Emails a fresh code and switches the UI to the code-entry step.
async function startOtp({ mode, name, email, password }, errorEl) {
  const code = generateOtp();
  let sent;
  try {
    sent = await sendOtpEmail(name, email, code);
  } catch (err) {
    showError(errorEl, err.message);
    return false;
  }
  pendingOtp = {
    mode,
    name,
    email,
    password,
    otpHash: await sha256Hex(`${email}:${code}`),
    expiresAt: Date.now() + OTP_TTL_MS,
    attempts: 0,
    lastSentAt: Date.now(),
  };
  showOtpStep(sent.demo ? code : null);
  return true;
}

function showOtpStep(demoCode) {
  authEl.loginForm.classList.add("hidden");
  authEl.signupForm.classList.add("hidden");
  authEl.authTabs.classList.add("hidden");
  authEl.otpForm.classList.remove("hidden");
  authEl.otpError.classList.add("hidden");
  authEl.otpInput.value = "";
  authEl.otpInfo.textContent = `We sent a ${OTP_LENGTH}-digit code to ${pendingOtp.email}. It expires in ${OTP_TTL_MS / 60000} minutes. Check your spam folder if you don't see it.`;
  if (demoCode)
    authEl.otpInfo.textContent += `  [DEMO MODE — your code is ${demoCode}]`;
  authEl.otpInput.focus();
  startOtpResendTimer();
}

function hideOtpStep() {
  pendingOtp = null;
  clearInterval(otpResendTimer);
  authEl.otpForm.classList.add("hidden");
  authEl.otpInput.value = "";
  authEl.authTabs.classList.remove("hidden");
}

function startOtpResendTimer() {
  clearInterval(otpResendTimer);
  const tick = () => {
    if (!pendingOtp) return clearInterval(otpResendTimer);
    const left = Math.ceil(
      (pendingOtp.lastSentAt + OTP_RESEND_COOLDOWN_MS - Date.now()) / 1000,
    );
    if (left > 0) {
      authEl.otpResendBtn.disabled = true;
      authEl.otpResendBtn.textContent = `Resend code (${left}s)`;
    } else {
      authEl.otpResendBtn.disabled = false;
      authEl.otpResendBtn.textContent = "Resend code";
      clearInterval(otpResendTimer);
    }
  };
  tick();
  otpResendTimer = setInterval(tick, 1000);
}

async function handleOtpSubmit(e) {
  e.preventDefault();
  authEl.otpError.classList.add("hidden");
  const p = pendingOtp;
  if (!p) return;

  if (Date.now() > p.expiresAt)
    return showError(
      authEl.otpError,
      "That code has expired. Request a new one.",
    );
  if (p.attempts >= OTP_MAX_ATTEMPTS)
    return showError(
      authEl.otpError,
      "Too many wrong attempts. Request a new code.",
    );

  const entered = authEl.otpInput.value.trim();
  if (!/^\d+$/.test(entered) || entered.length !== OTP_LENGTH) {
    return showError(
      authEl.otpError,
      `Enter the ${OTP_LENGTH}-digit code from your email.`,
    );
  }

  p.attempts += 1;
  if ((await sha256Hex(`${p.email}:${entered}`)) !== p.otpHash) {
    const left = OTP_MAX_ATTEMPTS - p.attempts;
    return showError(
      authEl.otpError,
      left > 0
        ? `Incorrect code. ${left} attempt${left === 1 ? "" : "s"} left.`
        : "Too many wrong attempts. Request a new code.",
    );
  }

  // Code is correct.
  const btn = authEl.otpForm.querySelector('button[type="submit"]');
  const { mode, name, email, password } = p;
  markVerifiedHere(email);

  if (mode === "login") {
    hideOtpStep();
    renderForUser(auth.currentUser); // now verified -> into the app
    return;
  }

  // Sign-up: create the account only now that the email is proven.
  setBusy(btn, true, "Creating account…");
  try {
    pendingOtp = null;
    await auth.signUp(email, password, name);
    authEl.signupForm.reset();
    // onAuthStateChanged fires and takes the person into the app.
  } catch (err) {
    unmarkVerifiedHere(email);
    hideOtpStep();
    switchTab(err.code === "auth/email-already-in-use" ? "login" : "signup");
    showError(
      err.code === "auth/email-already-in-use"
        ? authEl.loginError
        : authEl.signupError,
      friendlyAuthError(err),
    );
  } finally {
    setBusy(btn, false);
  }
}

async function handleOtpResend() {
  const p = pendingOtp;
  if (!p || Date.now() < p.lastSentAt + OTP_RESEND_COOLDOWN_MS) return;
  authEl.otpResendBtn.disabled = true;
  authEl.otpError.classList.add("hidden");
  const ok = await startOtp(p, authEl.otpError);
  if (!ok) authEl.otpResendBtn.disabled = false;
}

function handleOtpBack() {
  const mode = pendingOtp && pendingOtp.mode;
  hideOtpStep();
  if (mode === "signup") switchTab("signup");
  else if (auth) auth.signOut(); // login mode: drop the half-finished sign-in
}

// Builds the code-entry form (kept in JS so index.html needs no changes).
function buildOtpForm() {
  const style = document.createElement("style");
  style.textContent = `
    .otp-info { font-size: 12.5px; color: var(--text-secondary); line-height: 1.5; }
    #otpInput { letter-spacing: 0.4em; text-align: center; font-family: var(--font-mono); font-size: 18px; }
    .otp-actions { display: flex; gap: 8px; }
    .otp-actions .btn { flex: 1; justify-content: center; }
    .otp-actions .btn:disabled { opacity: 0.55; cursor: not-allowed; }
  `;
  document.head.appendChild(style);

  const form = document.createElement("form");
  form.id = "otpForm";
  form.className = "auth-form hidden";
  form.innerHTML = `
    <p class="otp-info" id="otpInfo"></p>
    <div class="form-row">
      <label for="otpInput">Verification code</label>
      <input type="text" id="otpInput" inputmode="numeric" autocomplete="one-time-code" maxlength="${OTP_LENGTH}" placeholder="••••••" required />
    </div>
    <p id="otpError" class="auth-error hidden"></p>
    <button type="submit" class="btn btn-primary auth-submit">Verify &amp; continue</button>
    <div class="otp-actions">
      <button type="button" class="btn btn-ghost" id="otpResendBtn">Resend code</button>
      <button type="button" class="btn btn-ghost" id="otpBackBtn">Back</button>
    </div>`;
  authEl.signupForm.insertAdjacentElement("afterend", form);

  authEl.otpForm = form;
  authEl.otpInfo = form.querySelector("#otpInfo");
  authEl.otpInput = form.querySelector("#otpInput");
  authEl.otpError = form.querySelector("#otpError");
  authEl.otpResendBtn = form.querySelector("#otpResendBtn");
  authEl.otpBackBtn = form.querySelector("#otpBackBtn");
  authEl.authTabs = document.querySelector(".auth-tabs");
}

/* ------------------------- React to sign-in state ------------------------- */

function renderForUser(user) {
  if (!user) {
    // signed out
    currentEmail = null;
    hideOtpStep();
    clearAppUI();
    showAuth();
    switchTab("login");
    return;
  }

  const email = user.email.toLowerCase();

  if (!isVerifiedHere(email)) {
    // password OK, but email not yet proven in this browser
    currentEmail = null;
    clearAppUI();
    showAuth();
    if (
      (!pendingOtp || pendingOtp.email !== email) &&
      otpSendingFor !== email
    ) {
      otpSendingFor = email; // guard against double-sending while the first email is in flight
      startOtp(
        { mode: "login", name: user.displayName, email },
        authEl.loginError,
      ).finally(() => {
        otpSendingFor = null;
      });
    }
    return;
  }

  const changed = email !== currentEmail; // verified -> into the app
  currentEmail = email;
  hideOtpStep();
  showApp(email, user.displayName);
  if (changed) resetForNewSession(); // load THIS account's data
}

/* ---------------------------------- Handlers ------------------------------------ */

function setBusy(btn, busy, label) {
  if (busy) {
    btn.dataset.label = btn.textContent;
    btn.textContent = label;
  } else {
    btn.textContent = btn.dataset.label || btn.textContent;
  }
  btn.disabled = busy;
}

async function handleLogin(e) {
  e.preventDefault();
  authEl.loginError.classList.add("hidden");

  const email = authEl.loginEmail.value.trim().toLowerCase();
  const password = authEl.loginPassword.value;
  const btn = authEl.loginForm.querySelector('button[type="submit"]');

  setBusy(btn, true, "Logging in…");
  try {
    await auth.signIn(email, password);
    authEl.loginForm.reset();
    // onAuthStateChanged -> renderForUser: emails a code if this browser isn't verified yet.
  } catch (err) {
    showError(authEl.loginError, friendlyAuthError(err));
  } finally {
    setBusy(btn, false);
  }
}

async function handleSignup(e) {
  e.preventDefault();
  authEl.signupError.classList.add("hidden");

  const name = authEl.signupName.value.trim();
  const email = authEl.signupEmail.value.trim().toLowerCase();
  const password = authEl.signupPassword.value;
  const btn = authEl.signupForm.querySelector('button[type="submit"]');

  if (password.length < 6) {
    return showError(
      authEl.signupError,
      "Password must be at least 6 characters.",
    );
  }

  // NEW: stop here if this email already has an account (no code is sent).
  if (auth.emailExists(email)) {
    switchTab("login");
    authEl.loginEmail.value = email;
    showError(
      authEl.loginError,
      `An account with ${email} already exists. Please log in.`,
    );
    authEl.loginPassword.focus();
    return;
  }

  setBusy(btn, true, "Checking email…");
  try {
    const check = await validateEmailForSignup(email); // format / typo / disposable / domain exists
    if (!check.ok) return showError(authEl.signupError, check.message);

    btn.textContent = "Sending code…";
    await startOtp(
      { mode: "signup", name, email, password },
      authEl.signupError,
    );
  } finally {
    setBusy(btn, false);
  }
}

function handleLogout() {
  if (auth) auth.signOut(); // onAuthStateChanged -> renderForUser(null)
}

/* ---------------------------------- Wiring -------------------------------------- */

buildOtpForm();
{
  const note = document.querySelector(".auth-note");
  if (note)
    note.textContent =
      "Accounts and subscription data are stored in this browser.";
}

authEl.loginTabBtn.addEventListener("click", () => switchTab("login"));
authEl.signupTabBtn.addEventListener("click", () => switchTab("signup"));
authEl.loginForm.addEventListener("submit", handleLogin);
authEl.signupForm.addEventListener("submit", handleSignup);
authEl.logoutBtn.addEventListener("click", handleLogout);

authEl.otpForm.addEventListener("submit", handleOtpSubmit);
authEl.otpResendBtn.addEventListener("click", handleOtpResend);
authEl.otpBackBtn.addEventListener("click", handleOtpBack);

function startAuth() {
  auth.onAuthStateChanged(renderForUser); // fires on load, login, logout
}
document.addEventListener("DOMContentLoaded", startAuth);

/* =====================================================================
   Subscription Tracker — App Logic
   ---------------------------------------------------------------------
   Plain JS, no build step, no framework, no backend required. All data
   lives in localStorage. The `api` object below keeps the same shape a
   real REST client would have (list/summary/create/update/remove) so the
   rendering code doesn't need to know the data is local.
   ===================================================================== */

/* ------------------------------ Config -------------------------------- */
// Data is stored per account: see userScopedKey() in the auth section above.

// Consistent color per category, cycling through the accent palette so
// the category chart and table pills always match.
const CATEGORY_COLORS = [
  "#57534E",
  "#8A857F",
  "#A8433A",
  "#3F6B4F",
  "#8A6A2F",
  "#4A5B7A",
  "#B38F6A",
  "#6B4E71",
];

/* ------------------------------- State ---------------------------------- */
const state = {
  subscriptions: [], // full list, already filtered
  summary: null, // { totalMonthly, totalYearly, activeCount, upcomingRenewalsCount, upcomingRenewals, spendByCategory }
  filters: { search: "", category: "", status: "" },
  editingId: null, // id of subscription currently open in the modal, or null when adding
};

/* -------------------------------- DOM refs -------------------------------- */
const el = {
  themeToggle: document.getElementById("themeToggle"),
  addSubBtn: document.getElementById("addSubBtn"),

  sumMonthly: document.getElementById("sumMonthly"),
  sumYearly: document.getElementById("sumYearly"),
  sumActive: document.getElementById("sumActive"),
  sumUpcoming: document.getElementById("sumUpcoming"),

  searchInput: document.getElementById("searchInput"),
  categoryFilter: document.getElementById("categoryFilter"),
  statusFilter: document.getElementById("statusFilter"),
  clearFiltersBtn: document.getElementById("clearFiltersBtn"),

  tableBody: document.getElementById("subTableBody"),
  emptyState: document.getElementById("emptyState"),

  categoryChart: document.getElementById("categoryChart"),
  upcomingList: document.getElementById("upcomingList"),

  modalOverlay: document.getElementById("modalOverlay"),
  modalTitle: document.getElementById("modalTitle"),
  closeModalBtn: document.getElementById("closeModalBtn"),
  cancelModalBtn: document.getElementById("cancelModalBtn"),
  deleteSubBtn: document.getElementById("deleteSubBtn"),
  subForm: document.getElementById("subForm"),

  subId: document.getElementById("subId"),
  subName: document.getElementById("subName"),
  subPrice: document.getElementById("subPrice"),
  subCycle: document.getElementById("subCycle"),
  subRenewal: document.getElementById("subRenewal"),
  subStatus: document.getElementById("subStatus"),
  subCategory: document.getElementById("subCategory"),
  subNotes: document.getElementById("subNotes"),
  subAutopay: document.getElementById("subAutopay"),
  subDomain: document.getElementById("subDomain"),

  importMsgBtn: document.getElementById("importMsgBtn"),
  importModalOverlay: document.getElementById("importModalOverlay"),
  closeImportModalBtn: document.getElementById("closeImportModalBtn"),
  cancelImportBtn: document.getElementById("cancelImportBtn"),
  clearImportBtn: document.getElementById("clearImportBtn"),
  parseImportBtn: document.getElementById("parseImportBtn"),
  importMsgText: document.getElementById("importMsgText"),
  importExampleSelect: document.getElementById("importExampleSelect"),
  importError: document.getElementById("importError"),

  toastContainer: document.getElementById("toastContainer"),
};

/* ============================ Local "database" ============================ */
// A tiny localStorage-backed store standing in for the REST backend.

function addDays(n) {
  const d = new Date();
  d.setDate(d.getDate() + n);
  return d.toISOString().slice(0, 10);
}

function seedData() {
  return [
    {
      id: cryptoId(),
      name: "Netflix",
      price: 15.49,
      billing_cycle: "monthly",
      renewal_date: addDays(4),
      status: "active",
      category: "Streaming",
      notes: "Family plan, split with sister",
      autopay: true,
    },
    {
      id: cryptoId(),
      name: "Spotify",
      price: 11.99,
      billing_cycle: "monthly",
      renewal_date: addDays(18),
      status: "active",
      category: "Streaming",
      notes: "",
      autopay: true,
    },
    {
      id: cryptoId(),
      name: "Adobe Creative Cloud",
      price: 599.88,
      billing_cycle: "yearly",
      renewal_date: addDays(120),
      status: "active",
      category: "Software",
      notes: "Renews every January",
      autopay: false,
    },
    {
      id: cryptoId(),
      name: "GitHub Pro",
      price: 4,
      billing_cycle: "monthly",
      renewal_date: addDays(-1),
      status: "active",
      category: "Software",
      notes: "",
      autopay: true,
    },
    {
      id: cryptoId(),
      name: "Gym Membership",
      price: 34.99,
      billing_cycle: "monthly",
      renewal_date: addDays(9),
      status: "paused",
      category: "Health",
      notes: "Paused while traveling",
      autopay: false,
    },
    {
      id: cryptoId(),
      name: "Cloud Storage 2TB",
      price: 9.99,
      billing_cycle: "monthly",
      renewal_date: addDays(-5),
      status: "cancelled",
      category: "Utilities",
      notes: "Switched providers",
      autopay: false,
    },
  ];
}

function cryptoId() {
  return crypto.randomUUID
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

// Each signed-in email has its own list. A brand-new account starts empty.
// If you want sample data for new accounts, use seedData() instead of [].
function loadStore() {
  const key = userScopedKey(SUBS_KEY_BASE);
  if (!key) return [];
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveStore(list) {
  const key = userScopedKey(SUBS_KEY_BASE);
  if (!key) return;
  localStorage.setItem(key, JSON.stringify(list));
}

function monthlyEquivalent(sub) {
  return sub.billing_cycle === "yearly" ? sub.price / 12 : sub.price;
}

/* ------------------------------- App logos ------------------------------- */
// Shows each service's logo (Netflix, Spotify, ...) next to its name.
// The logo comes from the service's website icon, using either the website the
// user typed in the form or a guess from the name. If nothing can be loaded,
// a coloured initial is shown instead, so it never looks broken.

const KNOWN_APP_DOMAINS = {
  "netflix": "netflix.com",
  "spotify": "spotify.com",
  "prime video": "primevideo.com",
  "amazon prime": "amazon.com",
  "amazon": "amazon.com",
  "audible": "audible.com",
  "hotstar": "hotstar.com",
  "disney": "disneyplus.com",
  "jiocinema": "jiocinema.com",
  "sonyliv": "sonyliv.com",
  "sony liv": "sonyliv.com",
  "zee5": "zee5.com",
  "youtube": "youtube.com",
  "apple music": "apple.com",
  "apple tv": "apple.com",
  "icloud": "icloud.com",
  "apple": "apple.com",
  "google one": "one.google.com",
  "google": "google.com",
  "adobe": "adobe.com",
  "creative cloud": "adobe.com",
  "microsoft": "microsoft.com",
  "office 365": "microsoft.com",
  "xbox": "xbox.com",
  "github": "github.com",
  "gitlab": "gitlab.com",
  "linkedin": "linkedin.com",
  "notion": "notion.so",
  "chatgpt": "chatgpt.com",
  "openai": "openai.com",
  "claude": "claude.ai",
  "canva": "canva.com",
  "figma": "figma.com",
  "dropbox": "dropbox.com",
  "zoom": "zoom.us",
  "slack": "slack.com",
  "grammarly": "grammarly.com",
  "duolingo": "duolingo.com",
  "coursera": "coursera.org",
  "udemy": "udemy.com",
  "skillshare": "skillshare.com",
  "medium": "medium.com",
  "crunchyroll": "crunchyroll.com",
  "paramount": "paramountplus.com",
  "twitch": "twitch.tv",
  "discord": "discord.com",
  "tinder": "tinder.com",
  "bumble": "bumble.com",
  "swiggy": "swiggy.com",
  "zomato": "zomato.com",
  "uber": "uber.com",
  "evernote": "evernote.com",
  "todoist": "todoist.com",
  "nordvpn": "nordvpn.com",
  "expressvpn": "expressvpn.com",
};

// Longest names first so "amazon prime" wins over "amazon".
const KNOWN_APP_KEYS = Object.keys(KNOWN_APP_DOMAINS).sort(
  (a, b) => b.length - a.length,
);

function guessDomain(name) {
  const norm = ` ${String(name || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim()} `;
  for (const key of KNOWN_APP_KEYS) {
    if (norm.includes(` ${key} `)) return KNOWN_APP_DOMAINS[key];
  }
  return "";
}

// "https://www.Netflix.com/in/" -> "netflix.com"
function cleanDomain(input) {
  let d = String(input || "").trim().toLowerCase();
  d = d.replace(/^[a-z]+:\/\//, "").replace(/^www\./, "");
  d = d.split(/[/?#]/)[0];
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d) ? d : "";
}

function domainFor(sub) {
  return cleanDomain(sub && sub.domain) || guessDomain(sub && sub.name);
}

function logoUrl(domain, px) {
  return `https://www.google.com/s2/favicons?domain=${encodeURIComponent(domain)}&sz=${px > 64 ? 128 : 64}`;
}

// A rounded tile: coloured initial underneath, logo image on top when found.
function appLogoHtml(sub, size = 36) {
  const name = (sub && sub.name ? sub.name : "").trim();
  const letter = escapeHtml((name.charAt(0) || "?").toUpperCase());
  const color = categoryColor(name || "?");
  const domain = domainFor(sub);
  const img = domain
    ? `<img src="${logoUrl(domain, size * 2)}" alt="" loading="lazy" referrerpolicy="no-referrer" onerror="this.remove()" />`
    : "";
  return `<span class="app-logo" style="--s:${size}px;--c:${color}" title="${escapeHtml(name)}">${letter}${img}</span>`;
}

// Live preview inside the Add / Edit window.
function updateLogoPreview() {
  const box = document.getElementById("logoPreview");
  const hint = document.getElementById("logoHint");
  if (!box) return;
  const draft = { name: el.subName.value, domain: el.subDomain.value };
  box.innerHTML = appLogoHtml(draft, 48);
  if (!hint) return;
  const typed = cleanDomain(draft.domain);
  const guessed = guessDomain(draft.name);
  if (el.subDomain.value.trim() && !typed) hint.textContent = "Enter a website like netflix.com";
  else if (typed) hint.textContent = `Logo from ${typed}`;
  else if (guessed) hint.textContent = `Logo found automatically (${guessed})`;
  else if (draft.name.trim()) hint.textContent = "No logo found. Add the website to show one.";
  else hint.textContent = "";
}

/* ------------------------------- Autopay engine ------------------------------- */
// When a subscription has autopay enabled and its renewal date has arrived
// (or passed), the site treats it as auto-billed and rolls the renewal
// date forward to the next cycle. Runs once per day per account.

function advanceRenewalDate(iso, cycle) {
  const d = new Date(`${iso}T00:00:00`);
  if (cycle === "yearly") d.setFullYear(d.getFullYear() + 1);
  else d.setMonth(d.getMonth() + 1);
  return d.toISOString().slice(0, 10);
}

function runAutopay() {
  const list = loadStore();
  const renewed = [];

  const updated = list.map((sub) => {
    if (sub.status !== "active" || !sub.autopay) return sub;

    let renewalDate = sub.renewal_date;
    let didRenew = false;
    // Roll forward past every cycle that's already due.
    while (daysUntil(renewalDate) <= 0) {
      renewalDate = advanceRenewalDate(renewalDate, sub.billing_cycle);
      didRenew = true;
    }

    if (!didRenew) return sub;
    const next = { ...sub, renewal_date: renewalDate };
    renewed.push(next);
    return next;
  });

  if (renewed.length > 0) saveStore(updated);
  return renewed;
}

function runAutopayIfDue() {
  const key = userScopedKey(AUTOPAY_KEY_BASE);
  if (!key) return [];
  const today = new Date().toISOString().slice(0, 10);
  if (localStorage.getItem(key) === today) return [];
  const renewed = runAutopay();
  localStorage.setItem(key, today);
  return renewed;
}

/* ============================ Email reminder engine ============================ */
// Emails the signed-in user when a subscription is about to end / renew.
// One email lists ALL due subscriptions (1 EmailJS request per run). Each
// (subscription + renewal date) is emailed only once, tracked per account.
//
// NOTE: a browser-only app can only send these while the app is open.

let reminderInFlight = false;

function getRemindersSent() {
  const key = userScopedKey(REMINDERS_KEY_BASE);
  if (!key) return {};
  try {
    return JSON.parse(localStorage.getItem(key)) || {};
  } catch {
    return {};
  }
}

function saveRemindersSent(map) {
  const key = userScopedKey(REMINDERS_KEY_BASE);
  if (!key) return;
  localStorage.setItem(key, JSON.stringify(map));
}

function reminderKey(sub) {
  return `${sub.id}|${sub.renewal_date}`;
}

// Subscriptions that need a heads-up right now.
function findDueReminders() {
  return loadStore()
    .filter((sub) => {
      if (sub.status !== "active") return false;
      const days = daysUntil(sub.renewal_date);
      if (days >= 0 && days <= REMINDER_DAYS_BEFORE) return true;
      // Non-autopay subscription whose end date already passed recently.
      return !sub.autopay && days < 0 && days >= -REMINDER_OVERDUE_DAYS;
    })
    .sort((a, b) => new Date(a.renewal_date) - new Date(b.renewal_date));
}

function describeReminder(sub) {
  const days = daysUntil(sub.renewal_date);
  const date = formatDate(sub.renewal_date);

  let when;
  if (days < 0)
    when = `ended on ${date} (${Math.abs(days)} day${Math.abs(days) === 1 ? "" : "s"} ago)`;
  else if (days === 0) when = `ends/renews TODAY (${date})`;
  else if (days === 1) when = `ends/renews tomorrow (${date})`;
  else when = `ends/renews in ${days} days (${date})`;

  const action = sub.autopay
    ? "Autopay is ON, so it will be charged automatically."
    : "Autopay is OFF, so renew it manually or cancel it if you no longer need it.";

  return { when, action };
}

function buildReminderHtml(items) {
  const rows = items
    .map((sub) => {
      const { when, action } = describeReminder(sub);
      return `<li style="margin-bottom:12px;">
        <strong>${escapeHtml(sub.name)}</strong> — ${formatMoney(sub.price)} / ${escapeHtml(sub.billing_cycle)}<br/>
        ${escapeHtml(when)}<br/>
        <span style="color:#666;">${escapeHtml(action)}</span>
      </li>`;
    })
    .join("");
  return `<ul style="padding-left:18px;margin:0;">${rows}</ul>`;
}

async function sendReminderEmail(name, email, items) {
  const { serviceId, reminderTemplateId, publicKey } = EMAILJS_CONFIG;
  if (
    !serviceId ||
    !publicKey ||
    !reminderTemplateId ||
    reminderTemplateId.startsWith("PASTE_")
  ) {
    throw new Error(
      "Reminder emails aren't set up yet. Add your reminder Template ID in EMAILJS_CONFIG.",
    );
  }

  let res;
  try {
    res = await fetch("https://api.emailjs.com/api/v1.0/email/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        service_id: serviceId,
        template_id: reminderTemplateId,
        user_id: publicKey,
        template_params: {
          to_email: email,
          to_name: name || email,
          app_name: "Subscription Tracker",
          subject: `Reminder: ${items.length} subscription${items.length === 1 ? "" : "s"} ending soon`,
          count: String(items.length),
          reminder_list: buildReminderHtml(items),
        },
      }),
    });
  } catch {
    throw new Error("Couldn't reach the email service.");
  }

  if (!res.ok) {
    const detail = (await res.text().catch(() => "")).slice(0, 140);
    throw new Error(
      `Couldn't send the reminder email (${res.status}). ${detail}`.trim(),
    );
  }
}

// force = true  -> ignore the "already sent" log (used by the test button).
async function checkAndSendReminders({ force = false } = {}) {
  const email = getSession();
  if (!email || reminderInFlight) return;

  const due = findDueReminders();
  const sent = getRemindersSent();

  // Keep the log small: drop entries for subscriptions that no longer exist
  // or whose renewal date changed.
  const liveKeys = new Set(loadStore().map(reminderKey));
  let pruned = false;
  for (const k of Object.keys(sent)) {
    if (!liveKeys.has(k)) {
      delete sent[k];
      pruned = true;
    }
  }
  if (pruned) saveRemindersSent(sent);

  const toSend = force ? due : due.filter((s) => !sent[reminderKey(s)]);

  if (toSend.length === 0) {
    if (force)
      toast(
        `No active subscriptions are ending in the next ${REMINDER_DAYS_BEFORE} days.`,
        "default",
      );
    return;
  }

  reminderInFlight = true;
  try {
    const name = auth.currentUser ? auth.currentUser.displayName : "";
    await sendReminderEmail(name, email, toSend);

    // Only mark as sent after EmailJS accepted the request.
    const today = new Date().toISOString().slice(0, 10);
    const fresh = getRemindersSent();
    for (const s of toSend) fresh[reminderKey(s)] = today;
    saveRemindersSent(fresh);

    toast(
      `Reminder email sent to ${email} for ${toSend.length} subscription${toSend.length === 1 ? "" : "s"}.`,
      "success",
    );
  } catch (err) {
    console.warn("Reminder email failed:", err);
    // Only bother the user with errors when they clicked the test button.
    if (force) toast(err.message, "error");
  } finally {
    reminderInFlight = false;
  }
}

// Adds an "Email reminder" button to the top bar (kept in JS so
// index.html needs no changes). Handy for testing the email.
function buildReminderButton() {
  const bar = document.querySelector(".topbar-actions");
  if (!bar || document.getElementById("remindNowBtn")) return;

  const btn = document.createElement("button");
  btn.id = "remindNowBtn";
  btn.className = "btn btn-ghost";
  btn.type = "button";
  btn.innerHTML = `<i data-lucide="mail"></i><span>Email reminder</span>`;
  btn.title = `Email me subscriptions ending in the next ${REMINDER_DAYS_BEFORE} days`;
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    await checkAndSendReminders({ force: true });
    btn.disabled = false;
  });

  const importBtn = document.getElementById("importMsgBtn");
  if (importBtn) bar.insertBefore(btn, importBtn);
  else bar.appendChild(btn);
}

/* =========================== Bank message parser =========================== */
// Best-effort extraction from a pasted bank SMS/notification. The user still
// reviews everything in the normal form before saving.

const MONTH_NAMES = [
  "jan", "feb", "mar", "apr", "may", "jun",
  "jul", "aug", "sep", "oct", "nov", "dec",
];
const NAME_BLACKLIST = new Set([
  "AUTO DEBIT", "AUTOPAY", "AUTO-DEBIT", "UPI", "NEFT", "RTGS", "IMPS",
  "AVL BAL", "A/C", "OTP", "EMI", "SMS", "BANK", "THANK YOU", "CARD",
  "BAL", "AVAILABLE",
]);

function parseDateParts(dayStr, midStr, yearStr) {
  const day = parseInt(dayStr, 10);
  let month;
  if (/^[A-Za-z]+$/.test(midStr)) {
    month = MONTH_NAMES.indexOf(midStr.slice(0, 3).toLowerCase());
  } else {
    month = parseInt(midStr, 10) - 1;
  }
  let year = parseInt(yearStr, 10);
  if (yearStr.length === 2) year += 2000;

  if (Number.isNaN(day) || Number.isNaN(month) || Number.isNaN(year))
    return null;
  if (month < 0 || month > 11 || day < 1 || day > 31) return null;

  return `${year}-${String(month + 1).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
}

function findDates(text) {
  const regex = /(\d{1,2})[\/\-\s](\d{1,2}|[A-Za-z]{3,9})[\/\-\s](\d{2,4})\b/g;
  const matches = [];
  let m;
  while ((m = regex.exec(text)) !== null) {
    const iso = parseDateParts(m[1], m[2], m[3]);
    if (iso) matches.push({ index: m.index, iso });
  }
  return matches;
}

function extractAmount(text) {
  const m = text.match(/(?:rs\.?|inr|₹)\s*[:.]?\s*([\d,]+(?:\.\d{1,2})?)/i);
  if (!m) return null;
  const value = parseFloat(m[1].replace(/,/g, ""));
  return Number.isNaN(value) ? null : value;
}

function extractName(text) {
  const patterns = [
    /(?:subscription\s+to|renewed?\s+for|autopay\s+(?:for|towards)|debited\s+.*?for|towards)\s+([A-Za-z0-9&.\-\s]{2,40}?)(?:\s+(?:worth|has|is|auto|autopay|on|avl|bal|will|registered|activated|charges?|charged|annual|monthly|yearly|plan|via)\b|[.,]|$)/i,
    /for\s+([A-Z][A-Za-z0-9&.\-\s]{1,30}?)(?:\s+(?:auto|autopay|on|avl|bal|annual|monthly|yearly|plan|via)\b|[.,]|$)/i,
  ];
  for (const re of patterns) {
    const m = text.match(re);
    if (m && m[1].trim().length >= 2) return m[1].trim();
  }
  // Fallback: first ALL-CAPS word/phrase not in the blacklist (banks often
  // put the merchant name in caps, e.g. "NETFLIX", "SPOTIFY").
  const capsMatches =
    text.match(/\b[A-Z][A-Z0-9]{2,}(?:\s[A-Z][A-Z0-9]{2,})?\b/g) || [];
  for (const candidate of capsMatches) {
    if (!NAME_BLACKLIST.has(candidate.toUpperCase())) return candidate.trim();
  }
  return "";
}

function extractCycle(text) {
  return /year|annual/i.test(text) ? "yearly" : "monthly";
}

function extractAutopay(text) {
  return /autopay|auto[\s-]?debit|standing instruction|mandate|auto[\s-]?renew|recurring/i.test(
    text,
  );
}

function parseBankMessage(rawText) {
  const text = rawText.trim();
  if (!text) return { error: "Paste a bank message first." };

  const amount = extractAmount(text);
  const name = extractName(text);
  if (amount === null && !name) {
    return {
      error:
        "Couldn't find an amount or a merchant name in that message. You can still add it manually.",
    };
  }

  const cycle = extractCycle(text);
  const autopay = extractAutopay(text);

  const renewalIdx = text.toLowerCase().indexOf("renewal");
  const dates = findDates(text);
  let renewalDate;

  if (renewalIdx !== -1) {
    const after = dates.filter((d) => d.index >= renewalIdx);
    if (after.length > 0) renewalDate = after[0].iso;
  }

  if (!renewalDate) {
    const txnDate =
      dates.length > 0 ? dates[0].iso : new Date().toISOString().slice(0, 10);
    renewalDate = advanceRenewalDate(txnDate, cycle);
  }

  return {
    name,
    price: amount ?? 0,
    billing_cycle: cycle,
    renewal_date: renewalDate,
    autopay,
    snippet: text.length > 140 ? `${text.slice(0, 140)}…` : text,
  };
}

function findMatchingSubscription(name) {
  if (!name) return null;
  const target = name.trim().toLowerCase();
  return (
    loadStore().find((s) => s.name.trim().toLowerCase() === target) || null
  );
}

/* Sample messages so different bank/format styles can be tried with one click. */
const SAMPLE_MESSAGES = {
  netflix:
    "Rs.499.00 debited from a/c XXXX1234 on 05-09-26 for NETFLIX Auto Debit. Avl Bal Rs.10,000.00",
  hotstar:
    "INR 149 debited via UPI Autopay for Hotstar on 01/09/2026. Avl Bal: INR 8,940.00",
  amazon:
    "Your subscription to Amazon Prime worth INR 1499 has been activated via UPI Autopay on 15-Sep-2026. Next renewal on 15-Sep-2027.",
  spotify:
    "An e-mandate for Rs.499.00 towards SPOTIFY has been registered on your account 04-09-26. This will be auto debited every month.",
  ms365:
    "Rs.9999.00 debited for MICROSOFT 365 ANNUAL PLAN via autopay on 05-09-2026.",
  linkedin:
    "Payment of Rs.129 to LINKEDIN PREMIUM was processed on 01-09-26 using your saved card.",
};

function handleExampleSelect() {
  const key = el.importExampleSelect.value;
  if (!key || !SAMPLE_MESSAGES[key]) return;
  el.importMsgText.value = SAMPLE_MESSAGES[key];
  el.importError.classList.add("hidden");
  el.importMsgText.focus();
}

function handleClearImport() {
  el.importMsgText.value = "";
  el.importExampleSelect.value = "";
  el.importError.classList.add("hidden");
  el.importMsgText.focus();
}

function openImportModal() {
  el.importMsgText.value = "";
  el.importExampleSelect.value = "";
  el.importError.classList.add("hidden");
  el.importModalOverlay.classList.remove("hidden");
  el.importMsgText.focus();
}

function closeImportModal() {
  el.importModalOverlay.classList.add("hidden");
}

function handleParseImport() {
  const result = parseBankMessage(el.importMsgText.value);

  if (result.error) {
    el.importError.textContent = result.error;
    el.importError.classList.remove("hidden");
    return;
  }

  const matched = findMatchingSubscription(result.name);
  closeImportModal();

  if (matched) {
    openModal("edit", {
      ...matched,
      price: result.price || matched.price,
      billing_cycle: result.billing_cycle,
      renewal_date: result.renewal_date,
      autopay: result.autopay,
      status: "active",
    });
    toast(
      `Detected an update for ${matched.name} — review and save.`,
      "default",
    );
  } else {
    openModal("add", {
      name: result.name,
      price: result.price,
      billing_cycle: result.billing_cycle,
      renewal_date: result.renewal_date,
      status: "active",
      category: "",
      notes: `Detected from bank message: "${result.snippet}"`,
      autopay: result.autopay,
    });
    toast(
      result.name
        ? `Detected ${result.name} — review and save.`
        : "Detected details — please add a name and review.",
      "default",
    );
  }
}

function computeSummary(fullList) {
  const active = fullList.filter((s) => s.status === "active");

  const totalMonthly = active.reduce((sum, s) => sum + monthlyEquivalent(s), 0);
  const totalYearly = totalMonthly * 12;

  const upcomingRenewals = active
    .filter((s) => {
      const days = daysUntil(s.renewal_date);
      return days >= 0 && days <= 7;
    })
    .sort((a, b) => new Date(a.renewal_date) - new Date(b.renewal_date));

  const byCategory = {};
  for (const s of active) {
    byCategory[s.category] =
      (byCategory[s.category] || 0) + monthlyEquivalent(s);
  }
  const spendByCategory = Object.entries(byCategory)
    .map(([category, monthlySpend]) => ({ category, monthlySpend }))
    .sort((a, b) => b.monthlySpend - a.monthlySpend);

  return {
    totalMonthly,
    totalYearly,
    activeCount: active.length,
    upcomingRenewalsCount: upcomingRenewals.length,
    upcomingRenewals,
    spendByCategory,
  };
}

function applyFilters(fullList, filters) {
  return fullList.filter((s) => {
    if (
      filters.search &&
      !s.name.toLowerCase().includes(filters.search.toLowerCase())
    )
      return false;
    if (filters.category && s.category !== filters.category) return false;
    if (filters.status && s.status !== filters.status) return false;
    return true;
  });
}

/* ================================ API layer ================================ */
// Same shape a fetch()-based client would have, backed by localStorage.

const api = {
  list: (filters) => Promise.resolve(applyFilters(loadStore(), filters)),

  summary: () => Promise.resolve(computeSummary(loadStore())),

  create: (data) => {
    const list = loadStore();
    const sub = { id: cryptoId(), ...data };
    list.push(sub);
    saveStore(list);
    return Promise.resolve(sub);
  },

  update: (id, data) => {
    const list = loadStore();
    const idx = list.findIndex((s) => s.id === id);
    if (idx === -1) return Promise.reject(new Error("Subscription not found."));
    list[idx] = { ...list[idx], ...data, id };
    saveStore(list);
    return Promise.resolve(list[idx]);
  },

  remove: (id) => {
    const list = loadStore();
    const next = list.filter((s) => s.id !== id);
    saveStore(next);
    return Promise.resolve(null);
  },
};

/* ============================== Data loading ================================ */

async function loadAll() {
  try {
    const renewed = runAutopayIfDue();
    for (const sub of renewed) {
      toast(
        `${sub.name} was renewed via autopay — next billing ${formatDate(sub.renewal_date)}.`,
        "success",
      );
    }

    const [subs, summary] = await Promise.all([
      fetchFilteredList(),
      api.summary(),
    ]);
    state.subscriptions = subs;
    state.summary = summary;
    renderSummaryCards();
    renderTable();
    renderCategoryChart();
    renderUpcoming();
    populateCategoryFilter();

    // Email the user about anything ending soon (once per renewal date).
    checkAndSendReminders();
  } catch (err) {
    toast(err.message || "Couldn't load your subscriptions.", "error");
  }
}

function fetchFilteredList() {
  return api.list(state.filters);
}

async function refreshList() {
  try {
    state.subscriptions = await fetchFilteredList();
    renderTable();
  } catch (err) {
    toast(err.message, "error");
  }
}

/* ================================ Rendering ================================= */

function formatMoney(n) {
  return `$${Number(n).toFixed(2)}`;
}

function formatDate(iso) {
  const d = new Date(`${iso}T00:00:00`);
  return d.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function daysUntil(iso) {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const target = new Date(`${iso}T00:00:00`);
  return Math.round((target - today) / (1000 * 60 * 60 * 24));
}

function categoryColor(category) {
  let hash = 0;
  for (let i = 0; i < category.length; i++)
    hash = category.charCodeAt(i) + ((hash << 5) - hash);
  return CATEGORY_COLORS[Math.abs(hash) % CATEGORY_COLORS.length];
}

function renderSummaryCards() {
  if (!state.summary) return;
  el.sumMonthly.textContent = formatMoney(state.summary.totalMonthly);
  el.sumYearly.textContent = formatMoney(state.summary.totalYearly);
  el.sumActive.textContent = state.summary.activeCount;
  el.sumUpcoming.textContent = state.summary.upcomingRenewalsCount;
}

function renderTable() {
  const rows = state.subscriptions;
  el.tableBody.innerHTML = "";

  if (rows.length === 0) {
    el.emptyState.classList.remove("hidden");
    return;
  }
  el.emptyState.classList.add("hidden");

  for (const sub of rows) {
    const tr = document.createElement("tr");
    tr.dataset.id = sub.id;

    const daysLeft = daysUntil(sub.renewal_date);
    const isSoon = sub.status === "active" && daysLeft >= 0 && daysLeft <= 7;

    tr.innerHTML = `
      <td>
        <div class="cell-app">
          ${appLogoHtml(sub, 38)}
          <div class="cell-app-text">
            <span class="cell-name">${escapeHtml(sub.name)}</span>
            ${sub.notes ? `<span class="cell-notes">${escapeHtml(sub.notes)}</span>` : ""}
          </div>
        </div>
      </td>
      <td>
        <span class="category-pill">
          <span class="category-dot" style="background:${categoryColor(sub.category)}"></span>
          ${escapeHtml(sub.category)}
        </span>
      </td>
      <td class="cell-cost">${formatMoney(sub.price)}</td>
      <td style="text-transform:capitalize">${sub.billing_cycle}</td>
      <td class="cell-renews ${isSoon ? "cell-renews-soon" : ""}">${formatDate(sub.renewal_date)}</td>
      <td>
        ${
          sub.autopay
            ? `<span class="autopay-badge autopay-on" title="Autopay enabled — renews automatically"><i data-lucide="zap"></i> On</span>`
            : `<span class="autopay-badge autopay-off" title="Autopay disabled">Off</span>`
        }
      </td>
      <td><span class="status-badge status-${sub.status}">${sub.status}</span></td>
      <td class="col-actions">
        <button class="row-menu-btn" aria-label="Edit ${escapeHtml(sub.name)}">
          <i data-lucide="pencil"></i>
        </button>
      </td>
    `;

    tr.addEventListener("click", () => openModal("edit", sub));
    el.tableBody.appendChild(tr);
  }

  refreshIcons();
}

function renderCategoryChart() {
  const data = state.summary?.spendByCategory || [];
  el.categoryChart.innerHTML = "";

  if (data.length === 0) {
    el.categoryChart.innerHTML = `<p class="chart-empty">No active subscriptions yet.</p>`;
    return;
  }

  const max = Math.max(...data.map((d) => d.monthlySpend));

  for (const { category, monthlySpend } of data) {
    const row = document.createElement("div");
    const pct = max > 0 ? Math.round((monthlySpend / max) * 100) : 0;
    row.innerHTML = `
      <div class="category-row-label">
        <span>${escapeHtml(category)}</span>
        <span>${formatMoney(monthlySpend)}/mo</span>
      </div>
      <div class="progress-track">
        <div class="progress-fill" style="width:100%; transform:scaleX(${pct / 100}); background:${categoryColor(category)}"></div>
      </div>
    `;
    el.categoryChart.appendChild(row);
  }
}

function renderUpcoming() {
  const items = state.summary?.upcomingRenewals || [];
  el.upcomingList.innerHTML = "";

  if (items.length === 0) {
    el.upcomingList.innerHTML = `<p class="upcoming-empty">Nothing renewing in the next 7 days.</p>`;
    return;
  }

  for (const sub of items) {
    const li = document.createElement("li");
    li.className = "upcoming-item";
    li.innerHTML = `
      <div class="upcoming-left">
        ${appLogoHtml(sub, 34)}
        <div>
          <div class="upcoming-item-name">${escapeHtml(sub.name)}</div>
          <div class="upcoming-item-date">${formatDate(sub.renewal_date)}</div>
        </div>
      </div>
      <div class="upcoming-item-price">${formatMoney(sub.price)}</div>
    `;
    el.upcomingList.appendChild(li);
  }
}

function populateCategoryFilter() {
  const current = el.categoryFilter.value;
  const allCategories = [...new Set(loadStore().map((s) => s.category))].sort();

  el.categoryFilter.innerHTML = `<option value="">All categories</option>`;
  for (const c of allCategories) {
    const opt = document.createElement("option");
    opt.value = c;
    opt.textContent = c;
    el.categoryFilter.appendChild(opt);
  }
  el.categoryFilter.value = current;
}

function refreshIcons() {
  if (window.lucide) window.lucide.createIcons();
}

// Minimal HTML-escaping so subscription names/notes can't break markup.
function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

/* ================================== Modal ==================================== */

function openModal(mode, sub = null) {
  state.editingId = mode === "edit" ? sub.id : null;
  el.modalTitle.textContent =
    mode === "edit" ? "Edit subscription" : "Add subscription";
  el.deleteSubBtn.classList.toggle("hidden", mode !== "edit");

  el.subId.value = sub?.id || "";
  el.subName.value = sub?.name || "";
  el.subPrice.value = sub?.price ?? "";
  el.subCycle.value = sub?.billing_cycle || "monthly";
  el.subRenewal.value = sub?.renewal_date || "";
  el.subStatus.value = sub?.status || "active";
  el.subCategory.value = sub?.category || "";
  el.subNotes.value = sub?.notes || "";
  el.subAutopay.checked = !!sub?.autopay;
  el.subDomain.value = sub?.domain || "";
  updateLogoPreview();

  el.modalOverlay.classList.remove("hidden");
  el.subName.focus();
}

function closeModal() {
  el.modalOverlay.classList.add("hidden");
  el.subForm.reset();
  state.editingId = null;
}

async function handleFormSubmit(e) {
  e.preventDefault();

  if (!el.subForm.reportValidity()) return;

  const payload = {
    name: el.subName.value.trim(),
    price: parseFloat(el.subPrice.value),
    billing_cycle: el.subCycle.value,
    renewal_date: el.subRenewal.value,
    status: el.subStatus.value,
    category: el.subCategory.value.trim() || "Other",
    notes: el.subNotes.value.trim(),
    autopay: el.subAutopay.checked,
    domain: cleanDomain(el.subDomain.value),
  };

  const saveBtn = document.getElementById("saveSubBtn");
  saveBtn.disabled = true;

  try {
    if (state.editingId) {
      await api.update(state.editingId, payload);
      toast("Subscription updated.", "success");
    } else {
      await api.create(payload);
      toast("Subscription added.", "success");
    }
    closeModal();
    await loadAll();
  } catch (err) {
    toast(err.message, "error");
  } finally {
    saveBtn.disabled = false;
  }
}

async function handleDelete() {
  if (!state.editingId) return;
  const confirmed = confirm("Delete this subscription? This can't be undone.");
  if (!confirmed) return;

  try {
    await api.remove(state.editingId);
    toast("Subscription deleted.", "success");
    closeModal();
    await loadAll();
  } catch (err) {
    toast(err.message, "error");
  }
}

/* =================================== Toasts ==================================== */

function toast(message, type = "default") {
  const t = document.createElement("div");
  t.className = `toast ${type === "error" ? "toast-error" : type === "success" ? "toast-success" : ""}`;
  t.textContent = message;
  el.toastContainer.appendChild(t);
  setTimeout(() => t.classList.add("leaving"), 2900);
  setTimeout(() => t.remove(), 3200);
}

/* =================================== Theme ===================================== */
// One source of truth for light/dark. Both toggle buttons (the landing-page
// one and the in-app one) go through setTheme(), so they can never disagree.

const THEME_KEY = "theme";
const THEME_META_COLORS = { light: "#d0ccc7", dark: "#000000" };
const THEME_TOGGLE_SELECTOR = "#themeToggle, #landingThemeToggle";

function getSavedTheme() {
  try {
    const t = localStorage.getItem(THEME_KEY);
    return t === "light" || t === "dark" ? t : null;
  } catch {
    return null; // storage blocked (private mode, strict settings)
  }
}

function getSystemTheme() {
  return window.matchMedia &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

function getCurrentTheme() {
  return document.documentElement.getAttribute("data-theme") === "dark"
    ? "dark"
    : "light";
}

// Paint the theme + keep every toggle button's a11y state in sync.
function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);

  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", THEME_META_COLORS[theme]);

  const label = theme === "dark" ? "Switch to light mode" : "Switch to dark mode";
  document.querySelectorAll(THEME_TOGGLE_SELECTOR).forEach((btn) => {
    btn.setAttribute("aria-pressed", String(theme === "dark"));
    btn.setAttribute("aria-label", label);
    btn.title = label;
  });
}

function setTheme(theme, { persist = true } = {}) {
  applyTheme(theme);
  if (!persist) return;
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    /* ignore: the theme still changes for this session */
  }
}

function toggleTheme() {
  const next = getCurrentTheme() === "dark" ? "light" : "dark";
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  // View Transitions cross-fade the whole page with opacity only (compositor).
  if (document.startViewTransition && !reduce) {
    document.startViewTransition(() => setTheme(next));
  } else {
    setTheme(next);
  }
}

function initTheme() {
  applyTheme(getSavedTheme() || getSystemTheme());

  // Follow the OS setting live, but only until the user picks a theme.
  const mq = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)");
  if (mq) {
    const onSystemChange = (e) => {
      if (!getSavedTheme()) applyTheme(e.matches ? "dark" : "light");
    };
    if (mq.addEventListener) mq.addEventListener("change", onSystemChange);
    else if (mq.addListener) mq.addListener(onSystemChange); // old Safari
  }

  // Keep other open tabs in step.
  window.addEventListener("storage", (e) => {
    if (e.key === THEME_KEY && (e.newValue === "light" || e.newValue === "dark")) {
      applyTheme(e.newValue);
    }
  });
}

// One delegated listener handles BOTH buttons. It runs in the capture phase and
// stops the event, so any older toggle handler (e.g. in landing.js) cannot fire
// a second time and flip the theme straight back.
function wireThemeToggles() {
  document.addEventListener(
    "click",
    (e) => {
      const btn = e.target.closest && e.target.closest(THEME_TOGGLE_SELECTOR);
      if (!btn) return;
      e.preventDefault();
      e.stopPropagation();
      toggleTheme();

      // Re-trigger the little spin animation from motion.css.
      btn.classList.remove("spin");
      void btn.offsetWidth;
      btn.classList.add("spin");
      setTimeout(() => btn.classList.remove("spin"), 600);
    },
    true
  );
}

/* ============================ Filters & debouncing ============================== */

function debounce(fn, delay) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}

const debouncedSearch = debounce(() => {
  state.filters.search = el.searchInput.value.trim();
  refreshList();
}, 300);

function clearFilters() {
  state.filters = { search: "", category: "", status: "" };
  el.searchInput.value = "";
  el.categoryFilter.value = "";
  el.statusFilter.value = "";
  refreshList();
}

/* ========================= Switching between accounts ========================= */

// Wipes everything the previous user could see (called on logout).
function clearAppUI() {
  closeModal();
  closeImportModal();
  state.subscriptions = [];
  state.summary = null;
  state.filters = { search: "", category: "", status: "" };
  el.searchInput.value = "";
  el.statusFilter.value = "";
  el.categoryFilter.innerHTML = `<option value="">All categories</option>`;
  el.tableBody.innerHTML = "";
  el.categoryChart.innerHTML = "";
  el.upcomingList.innerHTML = "";
  el.toastContainer.innerHTML = "";
}

// Called right after login/signup: reload the list for the new account.
function resetForNewSession() {
  clearAppUI();
  loadAll();
}

/* ================================ Event wiring =================================== */

function wireEvents() {
  wireThemeToggles();

  el.addSubBtn.addEventListener("click", () => openModal("add"));
  el.closeModalBtn.addEventListener("click", closeModal);
  el.cancelModalBtn.addEventListener("click", closeModal);
  el.modalOverlay.addEventListener("click", (e) => {
    if (e.target === el.modalOverlay) closeModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !el.modalOverlay.classList.contains("hidden"))
      closeModal();
    if (
      e.key === "Escape" &&
      !el.importModalOverlay.classList.contains("hidden")
    )
      closeImportModal();
  });

  el.importMsgBtn.addEventListener("click", openImportModal);
  el.closeImportModalBtn.addEventListener("click", closeImportModal);
  el.cancelImportBtn.addEventListener("click", closeImportModal);
  el.clearImportBtn.addEventListener("click", handleClearImport);
  el.parseImportBtn.addEventListener("click", handleParseImport);
  el.importExampleSelect.addEventListener("change", handleExampleSelect);
  el.importModalOverlay.addEventListener("click", (e) => {
    if (e.target === el.importModalOverlay) closeImportModal();
  });

  el.subForm.addEventListener("submit", handleFormSubmit);
  el.deleteSubBtn.addEventListener("click", handleDelete);
  el.subName.addEventListener("input", updateLogoPreview);
  el.subDomain.addEventListener("input", updateLogoPreview);

  el.searchInput.addEventListener("input", debouncedSearch);
  el.categoryFilter.addEventListener("change", () => {
    state.filters.category = el.categoryFilter.value;
    refreshList();
  });
  el.statusFilter.addEventListener("change", () => {
    state.filters.status = el.statusFilter.value;
    refreshList();
  });
  el.clearFiltersBtn.addEventListener("click", clearFilters);
}

/* =================================== Bootstrap ==================================== */

function init() {
  initTheme();
  wireEvents();
  buildReminderButton();
  refreshIcons();
  loadAll();

  // While the tab stays open, keep checking for subscriptions about to end.
  setInterval(() => {
    if (getSession()) checkAndSendReminders();
  }, REMINDER_CHECK_INTERVAL_MS);
}

document.addEventListener("DOMContentLoaded", init);


/* ##################################################################
   SOURCE: landing.js  -> PASTE ITS CONTENTS HERE (file was not uploaded)
   ################################################################## */

/* ##################################################################
   SOURCE: motion.js  (v2 — scroll reveal, scroll-spy, progress, ripple)
   Writes only classes and transforms; all visuals live in styles.css.
   ################################################################## */
(function motionModule() {
  if (window.__subtrackMotion) return; // safe if an old motion.js is still loaded
  window.__subtrackMotion = true;

  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

  /* 1. Scroll reveal ------------------------------------------------------ */
  // Siblings reveal with a 70ms stagger (via --d), capped so long grids stay quick.
  const reveals = $$(".lp-reveal");
  const groups = new Map();
  reveals.forEach((node) => {
    const p = node.parentElement;
    if (!groups.has(p)) groups.set(p, []);
    groups.get(p).push(node);
  });
  groups.forEach((nodes) => {
    nodes.forEach((n, i) => n.style.setProperty("--d", Math.min(i, 6) * 0.07 + "s"));
  });

  const markIn = (node) => {
    node.classList.add("in");
    // After the entrance finishes, swap to the short hover transitions.
    setTimeout(() => node.classList.add("done"), reduce ? 0 : 1100);
  };

  if (reduce || !("IntersectionObserver" in window)) {
    reveals.forEach(markIn);
  } else {
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (!e.isIntersecting) return;
          markIn(e.target);
          io.unobserve(e.target);
        });
      },
      { threshold: 0.15, rootMargin: "0px 0px -8% 0px" }
    );
    reveals.forEach((n) => io.observe(n));
  }

  /* 2. Scroll progress bar + nav shadow (one rAF-throttled listener) ---------- */
  const bar = document.createElement("div");
  bar.className = "lp-progress";
  bar.setAttribute("aria-hidden", "true");
  document.body.appendChild(bar);
  const nav = document.querySelector(".lp-nav");

  let ticking = false;
  const onScroll = () => {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      const max = document.documentElement.scrollHeight - window.innerHeight;
      bar.style.transform = "scaleX(" + (max > 0 ? Math.min(window.scrollY / max, 1) : 0) + ")";
      if (nav) nav.classList.toggle("scrolled", window.scrollY > 8);
      ticking = false;
    });
  };
  window.addEventListener("scroll", onScroll, { passive: true });
  window.addEventListener("resize", onScroll, { passive: true });
  onScroll();

  /* 3. Scroll-spy for the nav links --------------------------------------- */
  const links = $$(".lp-nav-links a[href^='#']");
  const sections = links
    .map((a) => document.querySelector(a.getAttribute("href")))
    .filter(Boolean);
  if (sections.length && "IntersectionObserver" in window) {
    const spy = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (!e.isIntersecting) return;
          links.forEach((a) =>
            a.classList.toggle("active", a.getAttribute("href") === "#" + e.target.id)
          );
        });
      },
      { rootMargin: "-40% 0px -55% 0px" }
    );
    sections.forEach((s) => spy.observe(s));
  }

  /* 4. Click ripple (buttons only; ripple is scale + opacity) --------------- */
  if (!reduce) {
    document.addEventListener("click", (e) => {
      const btn = e.target.closest && e.target.closest(".btn, .lp-btn");
      if (!btn || btn.disabled) return;
      const r = btn.getBoundingClientRect();
      const dot = document.createElement("span");
      dot.className = "ripple";
      dot.style.left = e.clientX - r.left + "px";
      dot.style.top = e.clientY - r.top + "px";
      btn.appendChild(dot);
      dot.addEventListener("animationend", () => dot.remove());
    });
  }
})();

/* ##################################################################
   SOURCE: landing.js  (v2 — rebuilt: "Get started" buttons, reviews + stars,
   back-to-top, footer year)
   ################################################################## */
(function landingModule() {
  if (window.__subtrackLanding) return;
  window.__subtrackLanding = true;

  const $ = (id) => document.getElementById(id);
  const esc = (s) =>
    String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---- 1. Log in / Get started buttons ---------------------------------- */
  // Every [data-open-auth] button switches the auth card to that tab,
  // scrolls to the top of the page and focuses the first field.
  document.addEventListener("click", (e) => {
    const btn = e.target.closest && e.target.closest("[data-open-auth]");
    if (!btn) return;
    e.preventDefault();
    const mode = btn.getAttribute("data-open-auth") === "signup" ? "signup" : "login";

    if (typeof switchTab === "function") switchTab(mode);
    const screen = $("authScreen");
    if (screen) screen.classList.remove("hidden");

    const top = $("top");
    if (top) top.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });

    const field = $(mode === "signup" ? "signupName" : "loginEmail");
    setTimeout(() => field && field.focus({ preventScroll: true }), reduce ? 0 : 450);
  });

  /* ---- 2. Reviews + star ratings ------------------------------------------ */
  const REVIEWS_KEY = "subtracker.reviews.v1";
  const PAGE = 3;
  const SEED = [
    { name: "Aarav M.", rating: 5, text: "Found three subscriptions I forgot I was paying for. Paid for itself in a week.", t: 1 },
    { name: "Priya S.", rating: 5, text: "Pasting a bank SMS and having everything filled in is genuinely brilliant.", t: 2 },
    { name: "Rahul K.", rating: 4, text: "Clean, fast and the renewal emails are exactly what I needed. Would love a mobile app.", t: 3 },
    { name: "Sneha D.", rating: 5, text: "Dark mode looks great and the category chart makes my spending obvious.", t: 4 },
    { name: "Vikram P.", rating: 4, text: "Simple and private. I like that my data stays in my browser.", t: 5 },
    { name: "Ananya R.", rating: 5, text: "Autopay dates rolling forward on their own is such a small thing that saves me a lot.", t: 6 },
  ];

  function loadReviews() {
    try {
      const raw = JSON.parse(localStorage.getItem(REVIEWS_KEY));
      if (Array.isArray(raw) && raw.length) return raw;
    } catch { /* fall through to seed */ }
    return SEED.slice();
  }
  function saveReviews(list) {
    try { localStorage.setItem(REVIEWS_KEY, JSON.stringify(list)); } catch { /* storage blocked */ }
  }

  let reviews = loadReviews();
  let shown = PAGE;
  let justAddedId = null;

  const stars = (n) =>
    `<span class="lp-stars" role="img" aria-label="${n} out of 5 stars">` +
    "★".repeat(n) + `<span class="off">${"★".repeat(5 - n)}</span></span>`;

  function renderSummary() {
    const box = $("ratingSummary");
    if (!box) return;
    const count = reviews.length;
    const avg = count ? reviews.reduce((s, r) => s + r.rating, 0) / count : 0;
    box.innerHTML = count
      ? `<strong>${avg.toFixed(1)}</strong>${stars(Math.round(avg))}<span>from ${count} review${count === 1 ? "" : "s"}</span>`
      : "<span>No reviews yet. Be the first!</span>";
  }

  function renderReviews() {
    const grid = $("reviewGrid");
    if (!grid) return;
    const ordered = reviews.slice().sort((a, b) => b.t - a.t);
    grid.innerHTML = ordered.slice(0, shown).map((r) => `
      <article class="lp-card lp-review${r.t === justAddedId ? " just-added" : ""}">
        ${stars(r.rating)}
        <blockquote>“${esc(r.text)}”</blockquote>
        <div class="lp-review-by">
          <span class="lp-avatar">${esc(r.name.trim().charAt(0).toUpperCase() || "?")}</span>
          <div><strong>${esc(r.name)}</strong><span>Verified user</span></div>
        </div>
      </article>`).join("");
    const more = $("moreReviewsBtn");
    if (more) more.classList.toggle("hidden", shown >= ordered.length);
    renderSummary();
  }

  // Star picker: five buttons that behave like a radio group.
  let picked = 0;
  const starBox = $("starInput");
  function paintPicker() {
    if (!starBox) return;
    starBox.querySelectorAll("button").forEach((b, i) => {
      const on = i < picked;
      b.classList.toggle("on", on);
      b.setAttribute("aria-checked", String(i + 1 === picked));
    });
  }
  if (starBox) {
    starBox.innerHTML = [1, 2, 3, 4, 5]
      .map((n) => `<button type="button" role="radio" aria-checked="false" aria-label="${n} star${n > 1 ? "s" : ""}" data-v="${n}">★</button>`)
      .join("");
    starBox.addEventListener("click", (e) => {
      const b = e.target.closest("button[data-v]");
      if (!b) return;
      picked = Number(b.dataset.v);
      paintPicker();
    });
    starBox.addEventListener("keydown", (e) => {
      if (e.key === "ArrowRight" || e.key === "ArrowUp") picked = Math.min(5, picked + 1);
      else if (e.key === "ArrowLeft" || e.key === "ArrowDown") picked = Math.max(1, picked - 1);
      else return;
      e.preventDefault();
      paintPicker();
    });
  }

  const form = $("reviewForm");
  if (form) {
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const err = $("reviewError");
      const name = $("reviewName").value.trim();
      const text = $("reviewText").value.trim();
      const fail = (m) => { err.textContent = m; err.classList.remove("hidden"); };
      if (!name) return fail("Please enter your name.");
      if (!picked) return fail("Please choose a star rating.");
      if (text.length < 10) return fail("Please write at least 10 characters.");
      err.classList.add("hidden");

      const review = { name, rating: picked, text, t: Date.now() };
      reviews.push(review);
      saveReviews(reviews);
      justAddedId = review.t;
      shown = Math.max(shown, PAGE);
      form.reset();
      picked = 0;
      paintPicker();
      renderReviews();
      const grid = $("reviewGrid");
      if (grid) grid.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "center" });
    });
  }

  const moreBtn = $("moreReviewsBtn");
  if (moreBtn) moreBtn.addEventListener("click", () => { shown += PAGE; renderReviews(); });

  renderReviews();

  /* ---- 3. Back to top + footer year ------------------------------------- */
  const topBtn = $("backToTop");
  if (topBtn) {
    window.addEventListener("scroll", () => topBtn.classList.toggle("hidden", window.scrollY < 600), { passive: true });
    topBtn.addEventListener("click", () => window.scrollTo({ top: 0, behavior: reduce ? "auto" : "smooth" }));
  }
  const yr = $("lpYear");
  if (yr) yr.textContent = new Date().getFullYear();
})();