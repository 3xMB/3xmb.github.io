(function () {
  "use strict";

  /* ===== CONFIG ===== */
  var PROFILE = {
    handle: "3xMB",
    name: "Moh Bacha",
    email: "Admin@3xmb.com",
    location: "Saudi Arabia",
    roles: ["Offensive Security Learner", "CTF Enthusiast", "Future Red Teamer"],
    socials: {
      GitHub: "https://github.com/3xMB",
      LinkedIn: "https://www.linkedin.com/in/",
      TryHackMe: "https://tryhackme.com/p/3xMB"
    },
    certs: [
      { name: "Google Cybersecurity Professional Certificate", issuer: "Google", date: "2025" },
      { name: "TryHackMe — Cybersecurity 101 Path", issuer: "THM", date: "2025" },
      { name: "eJPT v2", issuer: "INE/ElevenPaths", date: "In Progress" }
    ],
    cv_url: "#",
    site: "3xmb.com"
  };
var PORTFOLIO = {
  projects: [
    {
      name: "AttackBox",
      desc: "Automated recon & exploitation toolkit.",
      stack: "Python, Bash, Nmap, Gobuster",
      status: "In Development"
    },
    {
      name: "Patient Steps System",
      desc: "Full medical workflow tracker for clinics.",
      stack: "PHP, MySQL, JS",
      status: "Production"
    },
    {
      name: "Clinic Inventory System",
      desc: "GRN-based stock tracking system with QR codes.",
      stack: "PHP, MySQL",
      status: "Production"
    },
    {
      name: "3xMB Terminal",
      desc: "Interactive hacker-style portfolio.",
      stack: "JS, Canvas, CSS",
      status: "Active"
    }
  ]
};

  var THEMES = {
  matrix: {
    accent: "#00ff88",
    muted: "#7ee2b8",
    dim: "#2b6d57",
    bg: "#0b0f0c",
    bg2: "#050706",
    title: "Matrix Green",
    matrixColor: "#00ff88",
    glow: "0 0 8px rgba(0,255,136,0.45)"
  },

  neon: {
    accent: "#00e5ff",
    muted: "#9beaff",
    dim: "#2a6570",
    bg: "#07131a",
    bg2: "#01070a",
    title: "Neon Blue",
    matrixColor: "#00eaff",
    glow: "0 0 8px rgba(0,200,255,0.45)"
  },

  lava: {
    accent: "#ff7a00",
    muted: "#ffc48a",
    dim: "#7a4a24",
    bg: "#140800",
    bg2: "#0a0400",
    title: "Lava Fire",
    matrixColor: "#ff7a00",
    glow: "0 0 8px rgba(255,120,0,0.5)"
  },

  violet: {
    accent: "#b488ff",
    muted: "#e4d1ff",
    dim: "#6a4d91",
    bg: "#120c18",
    bg2: "#0a060e",
    title: "Violet Mist",
    matrixColor: "#c59bff",
    glow: "0 0 8px rgba(180,120,255,0.5)"
  },

  cyberred: {
    accent: "#ff3b3b",
    muted: "#ffb0b0",
    dim: "#782626",
    bg: "#180606",
    bg2: "#090202",
    title: "Cyber Red",
    matrixColor: "#ff4d4d",
    glow: "0 0 8px rgba(255,70,70,0.5)"
  }
};

var THEME_ORDER = Object.keys(THEMES);

  var screen, themeBtn, themeNameBadge;
  var loginOverlay, loginInput, loginError, terminalWrap;

  var STATE = {
    history: [],
    pointer: -1,
    path: "~/3xmb",
    booted: false,
    typing: true,
    typingMsPerChar: 8,
    typingMaxDelay: 900,
    username: "guest",
    autoMatches: [],
    autoBase: "",
    autoIndex: 0
  };

  /* ===== DOM READY ===== */
  document.addEventListener("DOMContentLoaded", function () {
    screen = document.getElementById("screen");
    themeBtn = document.getElementById("themeBtn");
    themeNameBadge = document.getElementById("themeName");
    loginOverlay = document.getElementById("login-screen");
    loginInput = document.getElementById("login-input");
    loginError = document.getElementById("login-error");
    terminalWrap = document.getElementById("terminal-wrap");

    initThemeButton();
    initLogin();
  });

  /* ===== COMMANDS ===== */
  var COMMANDS = {
    help: function () {
  return block([
    "Available commands:",
    "",
    "─── Core ─────────────────────────────",
    "help           — show this help menu",
    "clear          — clear the screen",
    "history        — show previously executed commands",
    "whoami         — show current user",
    "ls             — list available sections",
    "banner         — show the ASCII logo",
    "",
    "─── Portfolio & Info ─────────────────",
    "about          — who is 3xMB?",
    "certs          — show certifications",
    "skills         — hacking & tech stack",
    "projects       — show portfolio projects",
    "roadmap        — cybersecurity progress",
    "stats          — hacker stats",
    "experience     — work background",
    "socials        — links & profiles",
    "contact        — email & CV",
    "",
    "─── Themes ───────────────────────────",
    "theme          — list themes or set theme <name>",
    "theme random   — pick a random theme",
    "themeinfo      — show current theme details",
    "",
    "─── Hacking Tools ─────────────────────",
    "osint          — OSINT toolkit (whois, dns, ip, subs)",
    "recon          — recon engine (quick/full scan)",
    "exploit        — exploit simulations (smb, ftp, web)",
    "crypto         — crypto utilities (base64, rot13)",
    "ifconfig       — fake network interface info",
    "neofetch       — system-style info output",
    "",
    "─── Notes ─────────────────────────────",
    "notes          — cheat sheet of common commands",
    "",
    "Type <command> for more details."
  ].join("\n"));
},



    banner: function () { return block(asciiArt()); },
ls: function () {
  return block([
    "Sections:",
    "",
    "Core:       help  history  clear  banner  whoami",
    "Portfolio:  about  certs  skills  projects  roadmap  stats  experience",
    "Social:     socials  contact",
    "Themes:     theme  themeinfo  theme random",
    "Hacking:    osint  recon  exploit  crypto  ifconfig  neofetch",
    "Notes:      notes"
  ].join("\n"));
},

    whoami: function () { return line(currentUser() + "@" + PROFILE.site); },
themeinfo: function () {
  var t = THEMES[currentTheme()];
  var lines = [
    "Theme: " + currentTheme(),
    "Title: " + t.title,
    "Accent: " + t.accent,
    "Matrix Rain Color: " + t.matrixColor,
    "Glow: " + t.glow
  ];
  return block(lines.join("\n"));
},

"theme random": function () {
  var keys = Object.keys(THEMES);
  var r = keys[Math.floor(Math.random() * keys.length)];
  applyTheme(r, true);
  return line("Random theme selected → " + r);
},

"theme set": function (args) {
  var n = (args[0] || "").toLowerCase();
  if (!THEMES[n]) return line("Unknown theme: " + escapeHtml(n));
  applyTheme(n, true);
  return line("Theme changed to " + n);
},

    about: function () {
      var roles = PROFILE.roles.map(function (r) {
        return '<span class="badge">' + escapeHtml(r) + "</span>";
      }).join(" ");
      return block(
        "Hey, I'm " + PROFILE.name + " (aka <span class=\"green\">" + PROFILE.handle + "</span>)." + "\n\n" +
        "I'm a cybersecurity learner who's deep into red teaming, CTFs, and building tooling." + "\n" +
        "Right now I'm focusing on web app pentesting and methodical note-taking." + "\n\n" +
        roles + "\n\n" +
        "Arabic (مختصر):" + "\n" +
        "أنا محمد باشا (3xMB) 👨‍💻" + "\n" +
        "باحث في أمن المعلومات ومهتم بمجال الاختراق الأخلاقي والـ Red Teaming." + "\n" +
        "بحب أتعلم من التحديات (CTFs) وأبني أدوات تساعدني أطور نفسي في الـ OffSec." + "\n" +
        "خلصت شهادات أساسية زي Google Cybersecurity Certificate و Cybersecurity 101 من TryHackMe،" + "\n" +
        "وحاليًا ماشي في مسار eJPT → OSCP بإذن الله." + "\n\n" +
        "هدفي إني أكون Red Teamer قوي وأساهم في رفع مستوى الأمان والهجوم الدفاعي في الشركات. 🚀"
      );
    },

    skills: function () {
      return block([
        "Technical Skills:",
        "",
        "• Networking (TCP/IP, DNS, DHCP, VPN, Firewalls)",
        "• OSINT & Information Gathering",
        "• Nmap, Gobuster, Nikto",
        "• Metasploit Framework",
        "• Python & Bash scripting",
        "• HTML, CSS, JavaScript basics",
        "• Web Exploitation (LFI, RFI, XSS, CSRF, File Upload)",
        "• SQL Injection & DB Attacks",
        "• Host-based Attacks & Privilege Escalation (Linux/Windows)",
        "• Active Directory attacks",
        "• Burp Suite Professional",
        "• Wireshark & Packet Analysis",
        "• Password Attacks (hashcat, john)",
        "• Enumeration (SMB, FTP, SSH, SNMP)",
        "• Exploit Development (basic buffer overflows)"
      ].join("\n"));
    },

    notes: function () {
      return block([
        "Cheat Sheet (short):",
        "",
        "• nmap -sC -sV -oN scan.txt <target>",
        "• gobuster dir -u http://<target> -w wordlist.txt",
        "• ssh user@host",
        "• smbclient //host/share -U user",
        "• sqlmap -u \"http://site/item.php?id=1\" --batch",
        "• python3 -m http.server 8000",
        "• nc -lvnp 4444",
        "• whoami && id && uname -a",
        "",
        "Tip: keep things scripted, not manual."
      ].join("\n"));
    },

    certs: function () {
      if (!PROFILE.certs.length) return line("No certifications added yet.");
      var rows = PROFILE.certs.map(function (c) {
        return "• " + escapeHtml(c.name) + " — " + escapeHtml(c.issuer) + " (" + escapeHtml(c.date) + ")";
      }).join("\n");
      return block("Certifications (" + PROFILE.certs.length + "):\n\n" + rows);
    },

    socials: function () {
      var entries = Object.entries(PROFILE.socials).filter(function (pair) {
        return pair[1] && pair[1] !== "#";
      });
      var links = entries.map(function (pair) {
        return "• " + pair[0] + ": <a href=\"" + pair[1] + "\" target=\"_blank\" rel=\"noopener\">" + pair[1] + "</a>";
      }).join("\n");
      return block(links || "No socials added.");
    },

    contact: function () {
      var cv = (PROFILE.cv_url && PROFILE.cv_url !== "#")
        ? "\nCV: <a href=\"" + PROFILE.cv_url + "\" target=\"_blank\" rel=\"noopener\">Download</a>" : "";
      return block("Email: <a href=\"mailto:" + PROFILE.email + "\">" + PROFILE.email + "</a>" + cv);
    },

    neofetch: function () {
      var w = window.innerWidth || 0;
      var h = window.innerHeight || 0;
      var theme = currentTheme();
      var lines = [];
      lines.push("          3xMB");
      lines.push("       ─────────");
      lines.push("user      : " + currentUser());
      lines.push("host      : 3xmb.com");
      lines.push("os        : Browser sandbox");
      lines.push("shell     : 3xmb-terminal.js");
      lines.push("location  : " + PROFILE.location);
      lines.push("theme     : " + theme);
      lines.push("resolution: " + w + "x" + h);
      lines.push("roles     : " + PROFILE.roles.join(", "));
      return block(lines.join("\n"));
    },
projects: function () {
  var list = PORTFOLIO.projects.map(function(p) {
    return "• " + p.name +
           "\n  " + p.desc +
           "\n  stack: " + p.stack +
           "\n  status: " + p.status + "\n";
  }).join("\n");

  return block("Projects:\n\n" + list);
},
roadmap: function () {
  return block([
    "Cybersecurity Roadmap:",
    "",
    "[■■■■■■■■■■] eJPT  (100%)",
    "[■■■■□□□□□□] eWPT  (25%)",
    "[□□□□□□□□□□] eWPTX  (0%)",
    "[□□□□□□□□□□] eCPPT  (0%)",
    "[□□□□□□□□□□] OSCP   (0%)",
    "",
    "Red Team Path:",
    "[□□□□□□□□□□] CRTP",
    "[□□□□□□□□□□] CRTE",
    "",
    "Crypto CTF Path:",
    "[■■■■■■■■■■] fundamentals (100%)",
    "[■■■□□□□□□□] advanced (30%)",
  ].join("\n"));
},
stats: function () {
  return block([
    "3xMB Hacker Stats:",
    "",
    "• CTF Challenges Solved: 137",
    "• Specialties: crypto, misc, web",
    "• Coding Hours (last 30 days): ~92h",
    "• Commit Activity: High",
    "• Hacking Streak: 17 days",
    "• System Uptime: " + Math.floor(performance.now()/1000) + " sec",
  ].join("\n"));
},
osint: function (args) {
    if (!args.length) {
        return block("Usage:\n" +
            "osint --whois <domain>\n" +
            "osint --dns <domain>\n" +
            "osint --subs <domain>\n" +
            "osint --ip <ip-address>");
    }

    var flag = args[0];
    var target = args[1] || "";

    function anim(text) {
        return block("[*] " + text);
    }

    print(anim("Launching OSINT module…"), true);

    // ===== WHOIS =====
    if (flag === "--whois") {
        if (!target) return line("osint --whois <domain>");

        print(anim("Querying WHOIS registry for " + target + "..."), true);

        return fetch("https://api.hackertarget.com/whois/?q=" + target)
            .then(r => r.text())
            .then(txt => block(txt))
            .catch(_ => line("WHOIS lookup failed (blocked or offline)."));
    }

    // ===== DNS Lookup =====
    if (flag === "--dns") {
        if (!target) return line("osint --dns <domain>");

        print(anim("Resolving DNS records…"), true);

        return fetch("https://api.hackertarget.com/dnslookup/?q=" + target)
            .then(r => r.text())
            .then(txt => block(txt))
            .catch(_ => line("DNS lookup failed."));
    }

    // ===== IP Lookup =====
    if (flag === "--ip") {
        if (!target) return line("osint --ip <address>");

        print(anim("Gathering Geo-IP information…"), true);

        return fetch("https://api.hackertarget.com/geoip/?q=" + target)
            .then(r => r.text())
            .then(txt => block(txt))
            .catch(_ => line("IP lookup failed."));
    }

    // ===== Subdomain Enum (Fake realistic) =====
    if (flag === "--subs") {
        if (!target) return line("osint --subs <domain>");

        print(anim("Enumerating subdomains…"), true);

        var fake = [
            "dev." + target,
            "admin." + target,
            "api." + target,
            "backup." + target,
            "staging." + target,
            "vpn." + target
        ];

        return block(fake.map(s => "• " + s).join("\n"));
    }

    return line("Unknown OSINT flag. Try: osint --help");
},

experience: function () {
  return block([
    "Professional Experience:",
    "",
    "• Fitness Lead / Area Trainer Manager — 3.5 years",
    "  Managed 13+ trainers across 5 branches.",
    "  Achieved record PT sales & member satisfaction.",
    "",
    "• Quality and Business Development Manager — Medical Sector",
    "  Built SOPs, inventory systems, patient workflow automation.",
    "",
    "• Cybersecurity Learner — 3xMB",
    "  CTF player (crypto, misc, web) + OffSec training.",
  ].join("\n"));
},
recon: function (args) {
    if (!args.length) {
        return block("Usage:\n" +
            "recon --quick <target>\n" +
            "recon --full <target>");
    }

    var flag = args[0];
    var target = args[1];

    if (!target) return line("Target required.");

    print(block("[*] Starting reconnaissance on " + target + "…"), true);

    if (flag === "--quick") {
        return block([
            "Nmap Quick Scan:",
            "",
            "22/tcp   open   ssh",
            "80/tcp   open   http",
            "443/tcp  open   https",
            "",
            "Scan complete."
        ].join("\n"));
    }

    if (flag === "--full") {
        return block([
            "Nmap Full Scan:",
            "",
            "22/tcp   open     ssh",
            "80/tcp   open     http",
            "443/tcp  open     https",
            "3306/tcp open     mysql",
            "8080/tcp open     http-proxy",
            "",
            "Service Detection:",
            "• Apache 2.4.54",
            "• PHP 8.1",
            "",
            "Scan complete."
        ].join("\n"));
    }

    return line("Unknown recon flag.");
},
exploit: function (args) {
    if (!args.length) {
        return block("Usage:\n" +
            "exploit --smb <ip>\n" +
            "exploit --ftp <ip>\n" +
            "exploit --web <url>");
    }

    var flag = args[0];
    var target = args[1];

    if (!target) return line("Target required.");

    print(block("[*] Preparing exploitation modules…"), true);
    print(block("[*] Target: " + target), true);

    if (flag === "--smb") {
        return block([
            "[*] Checking SMB version…",
            "[*] Attempting anonymous login…",
            "[!] Vulnerable to SMB Ghost CVE-2020-0796",
            "[+] Exploit simulation complete."
        ].join("\n"));
    }

    if (flag === "--ftp") {
        return block([
            "[*] Connecting to FTP…",
            "[*] Trying anonymous login…",
            "[+] Login successful!",
            "[+] Directory listing:",
            "   /backup.zip",
            "   /db.sql",
            "",
            "[!] Potential sensitive files found."
        ].join("\n"));
    }

    if (flag === "--web") {
        return block([
            "[*] Testing SQL injection…",
            "[*] Payload: ' OR 1=1-- -",
            "",
            "[+] Login bypass successful!",
            "[+] Dumping sample database rows:",
            "id=1  username=admin  pass=hash123",
            "id=2  username=test   pass=pass",
        ].join("\n"));
    }

    return line("Unknown exploit flag.");
},
crypto: function (args) {
    if (!args.length) {
        return block("Usage:\n" +
            "crypto --b64-enc <text>\n" +
            "crypto --b64-dec <text>\n" +
            "crypto --rot13 <text>");
    }

    var flag = args[0];
    var text = args.slice(1).join(" ");

    if (!text) return line("Text required.");

    if (flag === "--b64-enc") {
        return line(btoa(text));
    }

    if (flag === "--b64-dec") {
        try {
            return line(atob(text));
        } catch (e) {
            return line("Invalid base64.");
        }
    }

    if (flag === "--rot13") {
        return line(
            text.replace(/[a-zA-Z]/g, function (c) {
                return String.fromCharCode(
                    (c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13)
                        ? c
                        : c - 26
                );
            })
        );
    }

    return line("Unknown crypto flag.");
},

tools: function () {
  return block([
    "Hacking Toolkit:",
    "",
    "Enumeration:",
    "• nmap, gobuster, ffuf, smbclient, enum4linux",
    "",
    "Exploitation:",
    "• metasploit, sqlmap, psexec, impacket",
    "",
    "Post-Exploitation:",
    "• linpeas, winpeas, bloodhound",
    "",
    "Crypto:",
    "• Python, SageMath",
  ].join("\n"));
},

    ifconfig: function () {
      var host = window.location.hostname || "127.0.0.1";
      var lines = [];
      lines.push("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500");
      lines.push("    inet " + host + "  netmask 255.255.255.0  broadcast 255.255.255.255");
      lines.push("    inet6 ::1  prefixlen 128  scopeid 0x10<host>");
      lines.push("    ether 3x:mb:3x:mb:3x:mb  txqueuelen 1000  (Ethernet)");
      lines.push("    RX packets 1337  bytes 77777 (77.7 KB)");
      lines.push("    TX packets 2048  bytes 13371337 (13.3 MB)");
      lines.push("");
      lines.push("# fetching public IP ...");
      var el = block(lines.join("\n"));

      try {
        fetch("https://api.ipify.org?format=json").then(function (res) {
          return res.json();
        }).then(function (data) {
          var extra = block("public ip: " + escapeHtml(data.ip) + "  (via ipify.org)");
          print(extra, true);
        })["catch"](function () {
          var extra2 = block("public ip: unavailable (blocked or offline)");
          print(extra2, true);
        });
      } catch (e) {
        var extra3 = block("public ip: unavailable");
        print(extra3, true);
      }

      return el;
    },

    sudo: function () {
      var u = currentUser();
      return block(
        "[sudo] password for " + u + ":\n" +
        "...\n" +
        "sudo: authentication is disabled in this demo terminal.\n" +
        "nice try 😈"
      );
    },

theme: function (args) {
  args = args || [];

  // no flags → help
  if (!args.length) {
    return block([
      "Theme command usage:",
      "",
      "theme --list           Show available themes",
      "theme --info           Show details about current theme",
      "theme --random         Apply a random theme",
      "theme --set <name>     Apply specific theme",
      "",
      "Example:",
      "theme --set neon"
    ].join("\n"));
  }

  var flag = args[0].toLowerCase();

  // ---- LIST THEMES ----
  if (flag === "--list") {
    var out = THEME_ORDER.map(function (n) {
      return (n === currentTheme() ? "• [" + n + "]" : "• " + n);
    }).join("\n");

    return block("Available Themes:\n\n" + out);
  }

  // ---- INFO ABOUT CURRENT THEME ----
  if (flag === "--info") {
    var t = THEMES[currentTheme()];
    var lines = [
      "Theme Info:",
      "",
      "Name: " + currentTheme(),
      "Title: " + t.title,
      "Accent: " + t.accent,
      "Muted: " + t.muted,
      "Dim: " + t.dim,
      "Matrix Color: " + t.matrixColor,
      "Glow: " + t.glow
    ];
    return block(lines.join("\n"));
  }

  // ---- RANDOM THEME ----
  if (flag === "--random") {
    var keys = THEME_ORDER;
    var r = keys[Math.floor(Math.random() * keys.length)];
    applyTheme(r, true);
    return line("Random theme applied → " + r);
  }

  // ---- SET THEME ----
  if (flag === "--set") {
    var name = (args[1] || "").toLowerCase();
    if (!name) return line("Usage: theme --set <name>");

    if (!THEMES[name]) {
      return line("Unknown theme: " + escapeHtml(name) +
                  "\nUse: theme --list to see available themes");
    }

    applyTheme(name, true);
    return line("Theme changed to → " + name);
  }

  // ---- UNKNOWN FLAG ----
  return block([
    "Unknown flag: " + flag,
    "",
    "Valid usage:",
    "theme --list",
    "theme --info",
    "theme --random",
    "theme --set <name>"
  ].join("\n"));
},

    history: function () {
      if (!STATE.history.length) return line("history: (empty)");
      var out = STATE.history
        .map(function (cmd, idx) { return (idx + 1) + "  " + escapeHtml(cmd); })
        .join("\n");
      return block(out);
    },

    clear: function () {
      screen.innerHTML = "";
      return "";
    }
  };

  /* ===== HELPERS ===== */
  function currentUser() {
    return STATE.username || PROFILE.handle.toLowerCase();
  }

  function asciiArt() {
    var y = (new Date()).getFullYear();
    var lines = [
      "   ____  __  __ ____  ",
      "  /___ \\/ / / /|___ \\\\ ",
      "   ___) / /_/ /  __) |",
      "  |__ <| '_  _| |__ < ",
      "  ___) | | | | ___) | ",
      " |____/|_| |_||____/  "
    ];
    return '<span class="ascii">' + lines.join("\n") + "</span>\n <span class=\"muted\">3xMB • " + y + "</span>";
  }

  function motd() {
    return block([
      "Message of the day:",
      "",
      "Welcome, " + currentUser() + ".",
      "Stay curious. Break things. Document everything.",
      "Use this console to show who you are as an attacker-minded learner."
    ].join("\n"));
  }

  function boot() {
    var saved = localStorage.getItem("3xmb_theme") || "matrix";
    applyTheme(saved, false);

    print(line("Booting 3xMB terminal environment..."), true);
    print(line("Mounting /home/" + currentUser() + " ..."), true);
    print(line("Loading offensive security modules..."), true);
    newline();
    print(line(asciiArt()), true);
    print(block("Welcome to <span class=\"green\">3xMB</span> interactive terminal. Type <span class=\"green\">help</span> to get started."), true);
    newline();
    print(motd(), true);
    newline();
    prompt();
    STATE.booted = true;
  }

  /* ===== PROMPT (contenteditable + history + autocomplete) ===== */
  function prompt() {
    var row = document.createElement("div");
    row.className = "input-line";

    var promptHtml =
      '<span class="prompt">' + currentUser() + '@' + PROFILE.site + '</span>' +
      ':<span class="path">' + STATE.path + '</span>$ ';

    row.innerHTML = promptHtml;

    var edit = document.createElement("div");
    edit.className = "input-edit";
    edit.contentEditable = true;
    edit.spellcheck = false;

    var cursor = document.createElement("span");
    cursor.className = "block-cursor";

    row.appendChild(edit);
    row.appendChild(cursor);
    screen.appendChild(row);

    focusInput(edit);
    scrollToBottom();

    edit.addEventListener("keydown", function (e) {
      if (e.key === "Enter") {
        e.preventDefault();
        cursor.remove();
        var val = (edit.textContent || "").trim();
        edit.contentEditable = false;
        edit.style.opacity = 0.6;
        run(val);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        navigateHistory(-1, edit);
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        navigateHistory(1, edit);
      } else if (e.key === "Tab") {
        e.preventDefault();
        autocomplete(edit);
      }
    });
  }

  function run(cmd) {
    if (cmd && cmd.length) {
      STATE.history.push(cmd);
      STATE.pointer = STATE.history.length;
    } else {
      STATE.pointer = STATE.history.length;
    }

    var parts = cmd.split(/\s+/);
    var name = (parts[0] || "").toLowerCase();
    var args = parts.slice(1);

    print(
      line(
        "<span class=\"prompt\">" + currentUser() + "@" + PROFILE.site +
        "</span>:<span class=\"path\">" + STATE.path + "</span>$ " +
        escapeHtml(cmd)
      ),
      false
    );

    var fn = COMMANDS[name] || function () {
      return line("command not found: " + escapeHtml(name || "") + ". Try <span class='green'>help</span>");
    };
    var out = fn(args);
    if (out) print(out, true);
    newline();
    prompt();
  }

  function navigateHistory(dir, edit) {
    if (!STATE.history.length) return;
    STATE.pointer = Math.max(0, Math.min(STATE.history.length - 1, STATE.pointer + dir));
    var cmd = STATE.history[STATE.pointer] || "";
    edit.textContent = cmd;
    setCaretToEnd(edit);
  }

  function autocomplete(edit) {
    var txt = (edit.textContent || "").trim();
    var names = Object.keys(COMMANDS);
    var names = Object.keys(COMMANDS)
  .concat(["--list", "--info", "--random", "--set"])
  .concat(THEME_ORDER);


    if (!txt) {
      var list = block("Commands: " + names.join("  "));
      print(list, true);
      return;
    }

    var matches = names.filter(function (n) { return n.indexOf(txt) === 0; });

    if (!matches.length) {
      return;
    }

    // لو مفيش نفس الـbase من قبل، ابدأ دورة جديدة
    if (STATE.autoBase !== txt) {
      STATE.autoBase = txt;
      STATE.autoMatches = matches;
      STATE.autoIndex = 0;
    } else {
      STATE.autoIndex = (STATE.autoIndex + 1) % STATE.autoMatches.length;
    }

    var choice = STATE.autoMatches[STATE.autoIndex];
    edit.textContent = choice;
    setCaretToEnd(edit);
  }

  function line(html) {
    var el = document.createElement("div");
    el.className = "line";
    el.innerHTML = html;
    return el;
  }

  function block(html) {
    var el = document.createElement("div");
    el.className = "line";
    el.innerHTML = html.replace(/\n/g, "<br/>");
    return el;
  }

  function newline() {
    screen.appendChild(document.createElement("div"));
  }

  function focusInput(el) {
    setTimeout(function () {
      el.focus();
      setCaretToEnd(el);
    }, 10);
  }

  function setCaretToEnd(el) {
    var range = document.createRange();
    range.selectNodeContents(el);
    range.collapse(false);
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }

  function scrollToBottom() {
    screen.scrollTo({ top: screen.scrollHeight });
  }

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, function (s) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[s];
    });
  }

  /* ===== Typing Effect ===== */
  function textLengthFromHTML(html) {
    var tmp = document.createElement("div");
    tmp.innerHTML = html.replace(/\n/g, " ");
    return (tmp.textContent || "").length;
  }

  function print(el, withTyping) {
    withTyping = !!withTyping && STATE.typing;
    if (!withTyping) {
      screen.appendChild(el);
      scrollToBottom();
      return;
    }
    var holder = document.createElement("div");
    var len = textLengthFromHTML(el.innerHTML);
    var delay = Math.min(STATE.typingMaxDelay, Math.max(250, len * STATE.typingMsPerChar));
    holder.className = "line";
    holder.innerHTML = "<span class=\"typing\">…</span>";
    screen.appendChild(holder);
    scrollToBottom();
    setTimeout(function () {
      holder.replaceWith(el);
      scrollToBottom();
    }, delay);
  }

  /* ===== THEMES ===== */
  function currentTheme() {
    return localStorage.getItem("3xmb_theme") || "matrix";
  }

function applyTheme(name, persist) {
  if (persist === void 0) persist = true;

  var t = THEMES[name] || THEMES.matrix;

  // نحدّث المتغيّرات
  document.documentElement.style.setProperty("--accent", t.accent);
  document.documentElement.style.setProperty("--muted", t.muted);
  document.documentElement.style.setProperty("--dim", t.dim);
  document.documentElement.style.setProperty("--bg", t.bg);
  document.documentElement.style.setProperty("--bg2", t.bg2);
  document.documentElement.style.setProperty("--glow", t.glow);
  document.documentElement.style.setProperty("--matrix-color", t.matrixColor);

  // نعمل كلاس مؤقت عشان الأنيميشن
  document.body.classList.add("theme-switching");

  // الخلفية بالـgradient الجديد
  document.body.style.background =
    "radial-gradient(1600px 900px at 20% -10%, " +
    shade(t.accent, -70) +
    " 0%, var(--bg) 40%, var(--bg2) 100%)";

  // اسم الثيم في البادج
  if (themeNameBadge) {
    themeNameBadge.textContent = t.title;
  }

  // نحفظ الثيم الحالي
  if (persist) {
    localStorage.setItem("3xmb_theme", name);
  }

  // نغيّر لون الماتريكس لو الدالة موجودة
  if (typeof setMatrixColor === "function") {
    setMatrixColor(t.matrixColor);
  }

  // نشيل الكلاس بعد الأنيميشن
  setTimeout(function () {
    document.body.classList.remove("theme-switching");
  }, 450);
}


  function shade(hex, amt) {
    var f = parseInt(hex.slice(1), 16),
      t = amt < 0 ? 0 : 255,
      p = Math.abs(amt) / 100;
    var R = f >> 16,
      G = (f >> 8) & 255,
      B = f & 255;
    return (
      "#" +
      (0x1000000 +
        (Math.round((t - R) * p) + R) * 0x10000 +
        (Math.round((t - G) * p) + G) * 0x100 +
        (Math.round((t - B) * p) + B))
        .toString(16)
        .slice(1)
    );
  }

  function initThemeButton() {
    if (!themeBtn) return;
    themeBtn.addEventListener("click", function () {
      var cur = currentTheme();
      var idx = THEME_ORDER.indexOf(cur);
      var next = THEME_ORDER[(idx + 1) % THEME_ORDER.length];
      applyTheme(next, true);
      print(line("Theme set to " + next), true);
    });
  }

  /* ===== LOGIN FLOW ===== */
  function initLogin() {
    if (!loginOverlay || !loginInput) {
      if (terminalWrap) terminalWrap.style.display = "grid";
      boot();
      return;
    }

    loginInput.focus();
    loginInput.addEventListener("keydown", function (e) {
      if (e.key === "Enter") {
        var v = loginInput.value.trim();
        if (!v) v = "guest";
        STATE.username = v.toLowerCase();
        loginInput.disabled = true;
        if (loginError) loginError.style.display = "none";
        playLoginSequence();
      }
    });
  }

  function playLoginSequence() {
    var log = document.getElementById("login-log");
    if (!log) {
      completeLogin();
      return;
    }

    log.innerHTML = "";

    var lines = [
      "[*] Initializing secure session...",
      "[*] Resolving identity for " + currentUser() + "...",
      "[*] Loading 3xMB offensive modules...",
      "[+] Access granted. Welcome, " + currentUser() + "."
    ];

    var i = 0;
    function step() {
      if (i >= lines.length) {
        setTimeout(completeLogin, 400);
        return;
      }
      var row = document.createElement("div");
      row.className = "login-log-line";
      row.textContent = lines[i++];
      log.appendChild(row);
      log.scrollTop = log.scrollHeight;
      setTimeout(step, 350);
    }
    step();
  }

  function completeLogin() {
    if (loginOverlay) {
      loginOverlay.classList.add("login-fade-out");
      setTimeout(function () {
        loginOverlay.style.display = "none";
        if (terminalWrap) terminalWrap.style.display = "grid";
        boot();
      }, 450);
    } else {
      if (terminalWrap) terminalWrap.style.display = "grid";
      boot();
    }
  }
})();
