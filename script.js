/* =====================================================================
   Password Strength Analyzer & Breach Checker — Application logic
   Moved out of index.html as part of the HTML5/CSS3/JS refactor.

   Uses, per the project synopsis:
     - Web Crypto API  (crypto.subtle.digest, crypto.getRandomValues)
     - Fetch API       (breach lookup against the HIBP Pwned Passwords API)
     - DOM API         (getElementById/querySelector, addEventListener,
                         textContent, classList, style)
     - Clipboard API   (navigator.clipboard.writeText)

   Security notes (see README for the full write-up):
     - The plaintext password never leaves the browser.
     - The breach check sends only the first 5 characters of a locally
       computed SHA-1 hash to the HIBP "range" endpoint (k-anonymity).
       The full hash and the full password are never transmitted.
     - The reuse checker hashes with SHA-256 locally and keeps only
       hashes + masked labels in memory (no plaintext, no storage,
       nothing written to localStorage/sessionStorage, nothing logged).
   ===================================================================== */

(function () {
  "use strict";

  /* -------------------------------------------------------------------
     Common / weak password list — used by the "not a common password"
     check in the requirement checklist.
     ------------------------------------------------------------------- */
  const COMMON = new Set([
    "password",
    "123456",
    "123456789",
    "qwerty",
    "abc123",
    "password1",
    "111111",
    "12345678",
    "1234567",
    "letmein",
    "monkey",
    "dragon",
    "iloveyou",
    "admin",
    "welcome",
    "login",
    "princess",
    "qwertyuiop",
    "solo",
    "master",
    "football",
    "shadow",
    "michael",
    "superman",
    "1q2w3e4r",
    "passw0rd",
    "trustno1",
    "000000",
    "password123",
    "hunter2",
    "starwars",
    "zaq1zaq1",
    "123123",
    "654321",
    "qwerty123",
    "admin123",
    "welcome123",
    "iloveu",
    "computer",
    "internet",
    "secret",
    "test",
    "testing",
    "guest",
    "default",
    "changeme",
    "baseball",
    "soccer",
    "football1",
    "1234",
    "12345",
    "123321",
    "1234567890",
    "0987654321",
    "987654321",
    "112233",
    "121212",
    "666666",
    "696969",
    "777777",
    "888888",
    "999999",
    "11111111",
    "00000000",
    "123456a",
    "a123456",
    "abcd1234",
    "abcdef",
    "abc12345",
    "asdfgh",
    "asdfghjkl",
    "asdf1234",
    "zxcvbnm",
    "qazwsx",
    "qazwsxedc",
    "1qaz2wsx",
    "q1w2e3r4",
    "q1w2e3r4t5",
    "qwerty1",
    "qwerty12",
    "qwertyui",
    "qwer1234",
    "password2",
    "password12",
    "password1234",
    "passw0rd1",
    "pass",
    "pass123",
    "pass1234",
    "passwd",
    "p@ssword",
    "p@ssw0rd",
    "admin1",
    "admin1234",
    "administrator",
    "root",
    "toor",
    "user",
    "demo",
    "sample",
    "welcome1",
    "welcome1234",
    "letmein1",
    "letmein123",
    "login123",
    "master123",
    "access",
    "access14",
    "dragon1",
    "monkey1",
    "monkey123",
    "shadow1",
    "sunshine",
    "sunshine1",
    "princess1",
    "iloveyou1",
    "iloveyou123",
    "loveyou",
    "lovely",
    "freedom",
    "whatever",
    "nothing",
    "summer",
    "summer2020",
    "winter",
    "spring",
    "autumn",
    "hello",
    "hello123",
    "hellohello",
    "hi123",
    "mypassword",
    "mypass",
    "mypassword1",
    "myname",
    "secret123",
    "secure",
    "security",
    "google",
    "google123",
    "facebook",
    "instagram",
    "youtube",
    "gmail",
    "yahoo",
    "hotmail",
    "india",
    "india123",
    "delhi",
    "mumbai",
    "bangalore",
    "kolkata",
    "chennai",
    "hyderabad",
    "cricket",
    "cricket1",
    "sachin",
    "kohli",
    "dhoni",
    "ronaldo",
    "messi",
    "barcelona",
    "liverpool",
    "chelsea",
    "arsenal",
    "manchester",
    "hockey",
    "tennis",
    "basketball",
    "batman",
    "spiderman",
    "pokemon",
    "naruto",
    "matrix",
    "samsung",
    "iphone",
    "apple",
    "orange",
    "banana",
    "cookie",
    "chocolate",
    "pepper",
    "ginger",
    "cheese",
    "coffee",
    "buster",
    "tigger",
    "tiger",
    "lion",
    "angel",
    "butterfly",
    "flower",
    "sexy",
    "cool",
    "killer",
    "ninja",
    "hacker",
    "hack",
    "pass@123",
    "password@123",
    "password@1",
    "password!",
    "password#1",
    "admin@123",
    "admin@1234",
    "welcome@123",
    "india@123",
    "test123",
    "test1234",
    "testtest",
    "guest123",
    "temp",
    "temp123",
    "changeme123",
    "default123",
    "abc",
    "abcabc",
    "aaaaaa",
    "aaaaaaaa",
    "qqqqqq",
    "zzzzzz",
    "ashley",
    "jennifer",
    "jessica",
    "daniel",
    "andrew",
    "charlie",
    "thomas",
    "robert",
    "matthew",
    "joshua",
    "hunter",
    "ranger",
    "harley",
    "jordan",
    "jordan23",
    "mustang",
    "ferrari",
    "porsche",
    "mercedes",
    "bmw",
    "yankees",
    "cowboys",
    "eagles",
    "rockstar",
    "superstar",
    "starwars1",
    "pass1word",
    "trustno",
    "1q2w3e",
    "1q2w3e4r5t",
    "zaq12wsx",
    "love",
    "love123",
    "loveme",
    "lover",
    "family",
    "friends",
    "forever",
    "baby",
    "babygirl",
    "angel1",
    "internet1",
    "computer1",
    "football123",
    "baseball1",
    "soccer1"
  ]);

  /* -------------------------------------------------------------------
     Common dictionary words (4+ letters). Used to spot passwords that
     are just "a word + some decoration", e.g. Password@123, Summer2024!
     These are matched as substrings after undoing leetspeak.
     ------------------------------------------------------------------- */
  const COMMON_WORDS = [
    "password", "passwd", "passw0rd", "welcome", "admin", "login", "letmein",
    "master", "dragon", "monkey", "shadow", "sunshine", "princess", "football",
    "baseball", "soccer", "hockey", "cricket", "batman", "superman",
    "spiderman", "starwars", "pokemon", "iloveyou", "loveyou", "freedom",
    "whatever", "qwerty", "azerty", "secret", "summer", "winter", "spring",
    "autumn", "hello", "computer", "internet", "google", "facebook",
    "instagram", "youtube", "india", "delhi", "mumbai", "chennai", "kolkata",
    "bangalore", "hyderabad", "welcome", "access", "secure", "security",
    "mypass", "myname", "trustno", "hunter", "ranger", "harley", "jordan",
    "mustang", "ferrari", "tiger", "angel", "butterfly", "flower", "cookie",
    "chocolate", "coffee", "ginger", "cheese", "killer", "ninja", "hacker",
    "sample", "testing", "guest", "default", "changeme", "temp", "user",
    "root", "demo", "love", "lover", "family", "friend", "forever", "baby",
    "sachin", "kohli", "dhoni", "ronaldo", "messi", "samsung", "iphone",
    "apple", "orange", "banana", "matrix", "naruto", "rockstar", "superstar"
  ];

  /* -------------------------------------------------------------------
     DOM references (DOM API)
     ------------------------------------------------------------------- */
  const pwInput = document.getElementById("pw");
  const nameInput = document.getElementById("nameInput");
  const dobInput = document.getElementById("dobInput");
  const toggleVis = document.getElementById("toggleVis");

  const dialFill = document.getElementById("dialFill");
  const scoreNum = document.getElementById("scoreNum");

  const verdictTag = document.getElementById("verdictTag");
  const verdictDesc = document.getElementById("verdictDesc");

  const entropyLine = document.getElementById("entropyLine");
  const entropyStatus = document.getElementById("entropyStatus");
  const leakStatus = document.getElementById("leakStatus");

  const checksEl = document.getElementById("checks");

  const genBtn = document.getElementById("genBtn");
  const suggText = document.getElementById("suggText");
  const copyBtn = document.getElementById("copyBtn");

  const vaultInput = document.getElementById("vaultInput");
  const addBtn = document.getElementById("addBtn");
  const vaultList = document.getElementById("vaultList");
  const reuseFlag = document.getElementById("reuseFlag");

  const CIRC = 2 * Math.PI * 50;

  // In-memory only. Never written to localStorage/sessionStorage/URLs.
  let savedHashes = [];
  let leakTimer = null;
  let analysisVersion = 0;

  /* -------------------------------------------------------------------
     Show / hide password (DOM API)
     ------------------------------------------------------------------- */
  toggleVis.addEventListener("click", () => {
    const showing = pwInput.type === "text";

    pwInput.type = showing ? "password" : "text";
    toggleVis.textContent = showing ? "SHOW" : "HIDE";
    toggleVis.setAttribute("aria-pressed", String(!showing));
  });

  /* -------------------------------------------------------------------
     Web Crypto API — local hashing helpers
     SHA-1 is used only for the k-anonymity breach lookup (HIBP's
     Pwned Passwords API is keyed by SHA-1). SHA-256 is used for the
     local reuse checker.
     ------------------------------------------------------------------- */
  async function sha1(str) {
    const buffer = await crypto.subtle.digest(
      "SHA-1",
      new TextEncoder().encode(str)
    );

    return Array
      .from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("")
      .toUpperCase();
  }

  async function sha256(str) {
    const buf = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(str)
    );

    return Array
      .from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /* -------------------------------------------------------------------
     Password strength analysis — entropy
     ------------------------------------------------------------------- */
  function poolSize(pw) {
    let n = 0;

    if (/[a-z]/.test(pw)) n += 26;
    if (/[A-Z]/.test(pw)) n += 26;
    if (/[0-9]/.test(pw)) n += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) n += 32;

    return n || 1;
  }

  // Shannon-style estimate: bits = length * log2(character-pool size).
  // This is an estimate of guessing resistance assuming a random
  // password drawn from that character pool — it is not an absolute
  // measure of real-world security (a 20-character random-looking
  // sentence can still be lower entropy than it looks, and a leaked
  // password can have "high" entropy and still be unsafe).
  function entropyBits(pw) {
    if (!pw) return 0;

    return pw.length * Math.log2(poolSize(pw));
  }

  function entropyLabel(bits) {
    if (bits < 28) return "Very weak";
    if (bits < 36) return "Weak";
    if (bits < 60) return "Fair";
    if (bits < 80) return "Good";
    if (bits < 100) return "Strong";

    return "Very strong";
  }

  /* -------------------------------------------------------------------
     Password strength analysis — pattern detection
     ------------------------------------------------------------------- */
  function hasSequential(pw) {
    const sequences = [
      "0123456789",
      "9876543210",
      "abcdefghijklmnopqrstuvwxyz",
      "zyxwvutsrqponmlkjihgfedcba",
      "qwertyuiop",
      "poiuytrewq",
      "asdfghjkl",
      "lkjhgfdsa",
      "zxcvbnm",
      "mnbvcxz"
    ];

    const low = pw.toLowerCase();

    for (const seq of sequences) {
      for (let i = 0; i <= seq.length - 3; i++) {
        const chunk = seq.slice(i, i + 3);

        if (low.includes(chunk)) {
          return true;
        }
      }
    }

    return false;
  }

  function hasRepeats(pw) {
    return /(.)\1\1/.test(pw);
  }

  // Repeated chunk such as "abab", "xyzxyz" or "1212".
  function hasRepeatedChunk(pw) {
    return /(.{2,})\1/.test(pw.toLowerCase());
  }

  // Four-digit year 1900-2099 (birth years, "2024", etc.).
  function hasYear(pw) {
    return /(?:19|20)\d{2}/.test(pw);
  }

  /* Leetspeak handling: @ -> a, 0 -> o, 3 -> e, $ -> s ... so that
     "P@ssw0rd" is recognised as "password". "1" can mean i or l, so
     both readings are tried. */
  const LEET = {
    "@": "a",
    "4": "a",
    "3": "e",
    "0": "o",
    "$": "s",
    "5": "s",
    "7": "t",
    "+": "t",
    "!": "i"
  };

  function leetVariants(text) {
    const base = Array.from(text, c => LEET[c] || c).join("");

    return [
      text,
      base.replace(/1/g, "i"),
      base.replace(/1/g, "l")
    ];
  }

  // True when the password is (or is just a decorated version of) an
  // entry on the common-password list: case changes, leetspeak, and
  // digits/symbols stuck on the start or end are all undone first.
  function isCommonPassword(pw) {
    if (!pw) return false;

    const low = pw.toLowerCase();
    const stripped = low.replace(/^[^a-z]+|[^a-z]+$/g, "");

    for (const base of [low, stripped]) {
      if (!base) continue;

      for (const candidate of leetVariants(base)) {
        if (COMMON.has(candidate)) return true;
      }
    }

    return false;
  }

  // Length of the longest common dictionary word found inside the
  // password (after undoing leetspeak). 0 means none found.
  function containsCommonWord(pw) {
    if (!pw) return 0;

    const variants = leetVariants(pw.toLowerCase());
    let longest = 0;

    for (const word of COMMON_WORDS) {
      if (word.length <= longest) continue;

      if (variants.some(v => v.includes(word))) {
        longest = word.length;
      }
    }

    return longest;
  }

  /* -------------------------------------------------------------------
     Effective entropy — raw entropy minus penalties for detected
     patterns. Raw entropy assumes every character is chosen at random;
     a dictionary word, a year or a keyboard run is far more guessable
     than that, so those parts are "re-priced" at a realistic cost:
       - exact common password ........ capped at 20 bits
       - dictionary word .............. ~11 bits instead of len x bits/char
       - 4-digit year ................. ~7 bits
       - sequence / repeated run ...... ~4 bits for a 3-char run
     ------------------------------------------------------------------- */
  function effectiveEntropy(pw, found) {
    if (!pw) return 0;

    const perChar = Math.log2(poolSize(pw));
    let bits = pw.length * perChar;

    if (found.common) return Math.min(bits, 20);

    if (found.wordLen) bits -= Math.max(0, found.wordLen * perChar - 11);
    if (found.year) bits -= Math.max(0, 4 * perChar - 7);
    if (found.sequence) bits -= Math.max(0, 3 * perChar - 4);

    return Math.max(0, bits);
  }

  function containsName(pw, name) {
    if (!name) return false;

    const password = pw.toLowerCase();

    const cleanName = name
      .toLowerCase()
      .replace(/[^a-z0-9]/g, "");

    if (cleanName.length < 3) return false;

    return password.includes(cleanName);
  }

  function containsDOB(pw, dob) {
    if (!dob) return false;

    const password = pw.toLowerCase();
    const date = new Date(dob + "T00:00:00");

    if (Number.isNaN(date.getTime())) return false;

    const day = String(date.getDate()).padStart(2, "0");
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const year = String(date.getFullYear());
    const shortYear = year.slice(-2);

    // Only 4+ digit combinations are checked. Two-digit pieces such as
    // "07" or "99" would flag far too many unrelated passwords.
    const formats = [
      day + month + year,
      month + day + year,
      year + month + day,
      day + month + shortYear,
      month + day + shortYear,
      year
    ];

    return formats.some(value => password.includes(value));
  }

  /* -------------------------------------------------------------------
     Password strength analysis — score & requirement checklist
     ------------------------------------------------------------------- */
  function analyze(pw) {
    const name = nameInput.value.trim();
    const dob = dobInput.value;

    const sequenceWeak =
      hasSequential(pw) ||
      hasRepeats(pw) ||
      hasRepeatedChunk(pw);

    const commonWeak = isCommonPassword(pw);
    const wordLen = containsCommonWord(pw);
    const yearWeak = hasYear(pw);

    const personalWeak =
      containsName(pw, name) ||
      containsDOB(pw, dob);

    const checks = {
      len: pw.length >= 12,
      upper: /[A-Z]/.test(pw),
      lower: /[a-z]/.test(pw),
      digit: /[0-9]/.test(pw),
      symbol: /[^a-zA-Z0-9]/.test(pw),
      sequence: pw.length > 0 && !sequenceWeak,
      personal: pw.length > 0 && !personalWeak,
      unique: pw.length > 0 && !commonWeak,
      words: pw.length > 0 && wordLen === 0,
      year: pw.length > 0 && !yearWeak
    };

    const rawBits = entropyBits(pw);

    const bits = effectiveEntropy(pw, {
      common: commonWeak,
      wordLen,
      year: yearWeak,
      sequence: sequenceWeak
    });

    let score = 0;

    if (pw.length) {
      // Weights: length 15 + variety/pattern checks 80 + entropy bonus 5
      // = 100, so a password can only reach 100 by passing everything.
      score += checks.len
        ? 15
        : Math.min(15, Math.round(pw.length / 12 * 15));

      score += checks.upper ? 10 : 0;
      score += checks.lower ? 10 : 0;
      score += checks.digit ? 10 : 0;
      score += checks.symbol ? 12 : 0;
      score += checks.sequence ? 10 : 0;
      score += checks.personal ? 5 : 0;
      score += checks.unique ? 10 : 0;
      score += checks.words ? 8 : 0;
      score += checks.year ? 5 : 0;

      score += Math.min(5, Math.round(bits / 20));

      score = Math.min(100, score);

      // Ceilings: ticking every "variety" box must not rescue a
      // password that is predictable (Password@123, Summer2024!, ...).
      if (!checks.unique) score = Math.min(score, 20);
      else if (!checks.words) score = Math.min(score, 49);
      else if (!checks.personal) score = Math.min(score, 49);

      if (bits < 28) score = Math.min(score, 34);

      // Failing the minimum length means the password can never be
      // rated "Strong", however varied it is.
      if (!checks.len) score = Math.min(score, 79);
    }

    return {
      checks,
      score,
      bits,
      rawBits,
      sequenceWeak,
      personalWeak
    };
  }

  function colorFor(score) {
    if (score === 0) return "#3a4568";
    if (score < 35) return "var(--weak)";
    if (score < 60) return "var(--fair)";
    if (score < 82) return "var(--good)";

    return "var(--strong)";
  }

  function verdictFor(score, pw) {
    if (!pw.length) {
      return {
        tag: "Awaiting input",
        desc: "Start typing to see how your password holds up.",
        color: "var(--sub)"
      };
    }

    if (score < 35) {
      return {
        tag: "Weak",
        desc: "Easy to guess. Add length, variety, and avoid predictable patterns.",
        color: "var(--weak)"
      };
    }

    if (score < 60) {
      return {
        tag: "Fair",
        desc: "Better, but predictable patterns or limited length still reduce security.",
        color: "var(--fair)"
      };
    }

    if (score < 82) {
      return {
        tag: "Good",
        desc: "A solid password. More length and unpredictability can make it stronger.",
        color: "var(--good)"
      };
    }

    return {
      tag: "Strong",
      desc: "High resistance to common guessing and brute-force attacks.",
      color: "var(--strong)"
    };
  }

  /* -------------------------------------------------------------------
     Breach checker — Have I Been Pwned "Pwned Passwords" range API
     using k-anonymity, via the Fetch API.

     Flow (see README for the full diagram):
       1. Hash the password locally with SHA-1 (Web Crypto API).
       2. Split into a 5-character prefix and the remaining suffix.
       3. Send ONLY the 5-character prefix to /range/<prefix>.
       4. The API returns every suffix sharing that prefix, each with
          a breach count.
       5. Compare the local suffix against the returned list locally.

     The full password and the full hash are never sent to the API.
     ------------------------------------------------------------------- */
  const BREACH_API_TIMEOUT_MS = 8000;

  async function checkLeakedPassword(pw, version) {
    if (!pw) {
      leakStatus.textContent = "Waiting for password...";
      leakStatus.className = "status-value status-wait";
      return;
    }

    leakStatus.textContent = "Checking known leaked passwords...";
    leakStatus.className = "status-value status-wait";

    // Guard: Web Crypto API requires a secure context (HTTPS or
    // localhost). GitHub Pages is HTTPS, so this only trips up a
    // plain http:// local file preview.
    if (!(window.crypto && window.crypto.subtle)) {
      leakStatus.textContent =
        "Leak check needs a secure context (HTTPS or localhost).";
      leakStatus.className = "status-value status-wait";
      return;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(
      () => controller.abort(),
      BREACH_API_TIMEOUT_MS
    );

    try {
      const hash = await sha1(pw);
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);

      let response;

      try {
        response = await fetch(
          `https://api.pwnedpasswords.com/range/${prefix}`,
          {
            headers: {
              "Add-Padding": "true"
            },
            signal: controller.signal
          }
        );
      } catch (networkError) {
        if (version !== analysisVersion) return;

        if (networkError.name === "AbortError") {
          leakStatus.textContent =
            "Leak check timed out. Check your connection and try again.";
        } else {
          leakStatus.textContent =
            "Could not reach the leak-check service. You may be offline.";
        }

        leakStatus.className = "status-value status-wait";
        return;
      }

      if (!response.ok) {
        if (version !== analysisVersion) return;

        leakStatus.textContent =
          `Leak-check service returned an error (HTTP ${response.status}). Try again shortly.`;
        leakStatus.className = "status-value status-wait";
        return;
      }

      let text;

      try {
        text = await response.text();
      } catch (readError) {
        if (version !== analysisVersion) return;

        leakStatus.textContent =
          "Received an unreadable response from the leak-check service.";
        leakStatus.className = "status-value status-wait";
        return;
      }

      if (version !== analysisVersion) return;

      const lines = text.split(/\r?\n/);
      let count = 0;
      let sawValidLine = false;

      for (const line of lines) {
        const parts = line.split(":");

        if (parts.length !== 2) continue;

        const returnedSuffix = parts[0].trim().toUpperCase();
        const occurrences = Number(parts[1].trim());

        if (!returnedSuffix || !Number.isFinite(occurrences)) continue;

        sawValidLine = true;

        if (returnedSuffix === suffix) {
          count = occurrences;
          break;
        }
      }

      if (!sawValidLine && text.trim().length > 0) {
        // Response didn't look like the expected "SUFFIX:COUNT" format.
        leakStatus.textContent =
          "Got an unexpected response from the leak-check service.";
        leakStatus.className = "status-value status-wait";
        return;
      }

      if (count > 0) {
        leakStatus.textContent =
          `⚠ Found ${count.toLocaleString()} time${count === 1 ? "" : "s"} in known leaked passwords.`;

        leakStatus.className = "status-value status-bad";
      } else {
        leakStatus.textContent =
          "✓ Not found in known leaked passwords.";

        leakStatus.className = "status-value status-good";
      }
    } catch (error) {
      if (version !== analysisVersion) return;

      leakStatus.textContent =
        "Could not complete the online leak check.";

      leakStatus.className = "status-value status-wait";
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /* -------------------------------------------------------------------
     Render — pulls analysis + breach state onto the page (DOM API)
     ------------------------------------------------------------------- */
  async function render() {
    const pw = pwInput.value;

    analysisVersion++;

    const currentVersion = analysisVersion;

    const {
      checks,
      score,
      bits,
      rawBits
    } = analyze(pw);

    const color = colorFor(score);

    dialFill.style.stroke = color;

    dialFill.style.strokeDasharray =
      `${(score / 100) * CIRC} ${CIRC}`;

    scoreNum.textContent = score;
    scoreNum.style.color = color;

    const v = verdictFor(score, pw);

    verdictTag.textContent = v.tag;
    verdictTag.style.color = v.color;
    verdictDesc.textContent = v.desc;

    if (pw.length) {
      const roundedBits = bits.toFixed(1);

      const note =
        rawBits - bits > 1
          ? ` · raw ${rawBits.toFixed(1)} bits before pattern penalties`
          : "";

      entropyLine.innerHTML =
        `Effective entropy: <b>${roundedBits} bits</b> · ${entropyLabel(bits)}${note}`;

      entropyStatus.textContent =
        `${roundedBits} bits — ${entropyLabel(bits)}`;

      entropyStatus.className =
        "status-value " +
        (bits >= 60 ? "status-good" : "status-wait");
    } else {
      entropyLine.innerHTML = "";

      entropyStatus.textContent =
        "Waiting for password...";

      entropyStatus.className =
        "status-value status-wait";
    }

    for (const li of checksEl.children) {
      const key = li.dataset.k;
      const pass = checks[key];

      li.classList.toggle("pass", pass);
      li.classList.toggle("fail", !pass);

      li.querySelector(".ico").textContent =
        pass ? "✓" : "✕";
    }

    if (!pw) {
      leakStatus.textContent =
        "Waiting for password...";

      leakStatus.className =
        "status-value status-wait";

      await checkReuse(pw);
      return;
    }

    clearTimeout(leakTimer);

    leakTimer = setTimeout(() => {
      checkLeakedPassword(pw, currentVersion);
    }, 700);

    await checkReuse(pw);
  }

  /* -------------------------------------------------------------------
     Password generator — Web Crypto API (crypto.getRandomValues)
     Security-sensitive randomness no longer uses Math.random().
     ------------------------------------------------------------------- */
  function randomInt(maxExclusive) {
    // Rejection sampling avoids modulo bias.
    const range = 256 - (256 % maxExclusive);
    const bytes = new Uint8Array(1);

    let value;

    do {
      crypto.getRandomValues(bytes);
      value = bytes[0];
    } while (value >= range);

    return value % maxExclusive;
  }

  function randomChar(set) {
    return set[randomInt(set.length)];
  }

  function generateStrong() {
    const lower = "abcdefghijkmnopqrstuvwxyz";
    const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    const digits = "23456789";
    const symbols = "!@#$%^&*-_=+?";

    const all = lower + upper + digits + symbols;

    let pw = [
      randomChar(lower),
      randomChar(upper),
      randomChar(digits),
      randomChar(symbols)
    ];

    for (let i = 0; i < 12; i++) {
      pw.push(randomChar(all));
    }

    // Fisher–Yates shuffle using crypto.getRandomValues via randomInt.
    for (let i = pw.length - 1; i > 0; i--) {
      const j = randomInt(i + 1);

      [pw[i], pw[j]] = [pw[j], pw[i]];
    }

    return pw.join("");
  }

  genBtn.addEventListener("click", () => {
    // Re-roll in the (rare) case random output happens to contain a
    // sequence, repeat, year or dictionary word.
    let generated = generateStrong();

    for (let i = 0; i < 25; i++) {
      const weak =
        hasSequential(generated) ||
        hasRepeats(generated) ||
        hasRepeatedChunk(generated) ||
        hasYear(generated) ||
        isCommonPassword(generated) ||
        containsCommonWord(generated) > 0;

      if (!weak) break;

      generated = generateStrong();
    }

    suggText.textContent = generated;
    suggText.classList.remove("ph");
  });

  /* -------------------------------------------------------------------
     Clipboard API
     ------------------------------------------------------------------- */
  copyBtn.addEventListener("click", async () => {
    const text = suggText.textContent;

    if (!text || suggText.classList.contains("ph")) {
      return;
    }

    const old = copyBtn.textContent;

    try {
      if (!navigator.clipboard || !navigator.clipboard.writeText) {
        throw new Error("Clipboard API unavailable");
      }

      await navigator.clipboard.writeText(text);

      copyBtn.textContent = "COPIED";
    } catch (error) {
      copyBtn.textContent = "COPY FAILED";
    } finally {
      setTimeout(() => {
        copyBtn.textContent = old;
      }, 1200);
    }
  });

  /* -------------------------------------------------------------------
     Password reuse checker — local SHA-256 comparison only.
     Nothing here is ever sent to a server, written to storage, put in
     a URL, or logged to the console.
     ------------------------------------------------------------------- */
  async function checkReuse(pw) {
    reuseFlag.classList.remove("show", "bad", "ok");

    if (!pw.length || savedHashes.length === 0) {
      return;
    }

    const h = await sha256(pw);

    const match = savedHashes.find(x => x.hash === h);

    reuseFlag.classList.add("show");

    if (match) {
      reuseFlag.classList.add("bad");

      reuseFlag.textContent =
        `⚠ Matches a saved password ("${match.label}"). Reusing old passwords weakens your security.`;
    } else {
      reuseFlag.classList.add("ok");

      reuseFlag.textContent =
        `✓ No match against ${savedHashes.length} saved password${savedHashes.length > 1 ? "s" : ""}.`;
    }
  }

  async function addToVault() {
    const val = vaultInput.value;

    if (!val) return;

    const hash = await sha256(val);

    const label =
      val.length <= 2
        ? val
        : val[0] +
          "•".repeat(Math.max(1, val.length - 2)) +
          val[val.length - 1];

    savedHashes.push({
      hash,
      label
    });

    const li = document.createElement("li");

    const left = document.createElement("span");
    left.textContent = label;

    const right = document.createElement("span");
    right.className = "h";
    right.textContent = hash.slice(0, 10) + "…";

    li.appendChild(left);
    li.appendChild(right);

    vaultList.appendChild(li);

    vaultInput.value = "";

    await checkReuse(pwInput.value);
  }

  addBtn.addEventListener("click", addToVault);

  vaultInput.addEventListener("keydown", event => {
    if (event.key === "Enter") {
      event.preventDefault();
      addToVault();
    }
  });

  /* -------------------------------------------------------------------
     Wire up live analysis + boot
     ------------------------------------------------------------------- */
  pwInput.addEventListener("input", render);
  nameInput.addEventListener("input", render);
  dobInput.addEventListener("change", render);

  render();
})();
