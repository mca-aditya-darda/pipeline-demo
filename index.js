const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const lodash = require('lodash');
const minimist = require('minimist');

const app = express();
const PORT = process.env.PORT || 3000;

// Setup in-memory SQLite database
const db = new sqlite3.Database(':memory:');

db.serialize(() => {
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    secret_token TEXT NOT NULL
  )`);

  const stmt = db.prepare("INSERT INTO users (username, email, role, secret_token) VALUES (?, ?, ?, ?)");
  stmt.run("admin", "admin@vulnshield.local", "Administrator", "FLAG{s3cur3_db_4cc3ss_772}");
  stmt.run("alice", "alice@example.com", "User", "FLAG{al1c3_pr1v4cy_991}");
  stmt.run("bob", "bob@example.com", "User", "FLAG{b0b_p4ssw0rd_334}");
  stmt.run("hacker_demo", "hacker@demo.local", "Pentester", "FLAG{dem0_sc3n4r10_884}");
  stmt.finalize();

  db.run(`CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL
  )`);

  const prodStmt = db.prepare("INSERT INTO products (name, category, price) VALUES (?, ?, ?)");
  prodStmt.run("Cyber Shield Firewall", "Security", 299.99);
  prodStmt.run("Quantum Rootkey", "Hardware", 1250.00);
  prodStmt.run("Kernel Exploiter Toolkit", "Software", 49.99);
  prodStmt.run("Stealth VPN Router", "Networking", 189.50);
  prodStmt.finalize();
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Create logs folder for path traversal demonstrations
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir);
}
fs.writeFileSync(path.join(logsDir, 'system.log'), 'System started successfully.\nAll modules active.\nWarning: Connection rate limit skipped for local interfaces.');
fs.writeFileSync(path.join(logsDir, 'application.log'), 'Application launched at localhost:3000\nDatabase in-memory initialized.\nSession tokens configured.');
fs.writeFileSync(path.join(__dirname, 'secret_flag.txt'), 'CONGRATULATIONS! You have successfully exploited a Local File Inclusion / Path Traversal vulnerability! FLAG{traversal_master_2026}');

// ------------------------------------------------------------
// 1. Reflected XSS Endpoint
// ------------------------------------------------------------
// Vulnerable: Directly renders name query parameter unescaped
app.get('/api/xss/vuln', (req, res) => {
  const name = req.query.name || 'Guest';
  // Send HTML back directly containing the unescaped query parameter
  res.send(`<span>Hello, ${name}! Welcome back to your portal.</span>`);
});

// Secure: Escapes special characters before outputting
app.get('/api/xss/secure', (req, res) => {
  const name = req.query.name || 'Guest';
  const escapedName = name
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
  res.send(`<span>Hello, ${escapedName}! Welcome back to your portal.</span>`);
});


// ------------------------------------------------------------
// 2. SQL Injection Endpoint
// ------------------------------------------------------------
// Vulnerable: Directly concatenates raw user inputs into the SQL query string
app.get('/api/sqli/vuln', (req, res) => {
  const category = req.query.category || '';
  const query = `SELECT name, category, price FROM products WHERE category = '${category}'`;

  db.all(query, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message, query });
    }
    res.json({ results: rows, query });
  });
});

// Secure: Uses parameterized queries (prepared statements)
app.get('/api/sqli/secure', (req, res) => {
  const category = req.query.category || '';
  const query = `SELECT name, category, price FROM products WHERE category = ?`;

  db.all(query, [category], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message, query });
    }
    res.json({ results: rows, query });
  });
});


// ------------------------------------------------------------
// 3. Command Injection Endpoint
// ------------------------------------------------------------
// Vulnerable: Directly passes parameter input to child_process.exec shell Command
app.post('/api/cmd/vuln', (req, res) => {
  const ip = req.body.ip || '127.0.0.1';
  // Standard ping command. On Windows we specify -n 2, on Unix -c 2.
  const isWindows = process.platform === 'win32';
  const pingCmd = isWindows ? `ping -n 2 ${ip}` : `ping -c 2 ${ip}`;

  exec(pingCmd, (err, stdout, stderr) => {
    res.json({
      command: pingCmd,
      output: stdout || stderr || err?.message || 'No response'
    });
  });
});

// Secure: Validates input to strictly allow only valid IP addresses / hostnames
// And ideally uses spawn or execFile instead of exec with a shell
app.post('/api/cmd/secure', (req, res) => {
  const ip = req.body.ip || '127.0.0.1';
  
  // Strict regex check for a valid IPv4 address or simple hostname
  const ipRegex = /^[a-zA-Z0-9.-]+$/;
  if (!ipRegex.test(ip)) {
    return res.json({
      command: 'Rejected due to validation rules',
      output: 'Error: Invalid characters detected in IP Address/Hostname. Input must contain only alphanumeric characters, dots, or dashes.'
    });
  }

  // Safe approach: use execFile or validation with exec.
  // Here we use exec with our validated clean input string.
  const isWindows = process.platform === 'win32';
  const pingCmd = isWindows ? `ping -n 2 ${ip}` : `ping -c 2 ${ip}`;

  exec(pingCmd, (err, stdout, stderr) => {
    res.json({
      command: pingCmd,
      output: stdout || stderr || err?.message || 'No response'
    });
  });
});


// ------------------------------------------------------------
// 4. Path Traversal Endpoint
// ------------------------------------------------------------
// Vulnerable: Directly appends user parameter to local path without validation
app.get('/api/path/vuln', (req, res) => {
  const filename = req.query.filename || 'system.log';
  const filepath = path.join(logsDir, filename);

  fs.readFile(filepath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).json({ error: `File not found: ${filepath}`, code: err.code });
    }
    res.json({ filename, content: data, filepath });
  });
});

// Secure: Ensures resolved file stays inside the designated logs directory
app.get('/api/path/secure', (req, res) => {
  const filename = req.query.filename || 'system.log';
  
  // 1. Resolve safe absolute path
  const safeBase = path.resolve(logsDir);
  const candidatePath = path.resolve(path.join(logsDir, filename));
  
  // 2. Prevent directory traversal out of the safe boundary
  if (!candidatePath.startsWith(safeBase)) {
    return res.status(403).json({
      error: 'Access Denied: Attempted path traversal out of sandbox boundary.',
      filepath: candidatePath
    });
  }

  fs.readFile(candidatePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).json({ error: 'File not found.', code: err.code });
    }
    res.json({ filename, content: data, filepath: candidatePath });
  });
});


// ------------------------------------------------------------
// 5. Prototype Pollution (Outdated Dependency: lodash 4.17.19)
// ------------------------------------------------------------
// Vulnerable: Directly merges user payload using vulnerable lodash.merge
app.post('/api/dep/vuln', (req, res) => {
  const payload = req.body.payload || '{}';
  try {
    const parsed = JSON.parse(payload);
    
    // Clear any previous pollution in the global object prototype
    delete Object.prototype.polluted;
    
    // Vulnerable lodash.merge allows __proto__ property injection which overrides Object.prototype
    const targetObj = {};
    lodash.merge(targetObj, parsed);

    const isPolluted = ({}).polluted;

    res.json({
      message: isPolluted ? 'Successfully polluted Object.prototype!' : 'Merge completed without pollution.',
      objectPrototypePollutedValue: ({}).polluted,
      isPolluted: !!isPolluted,
      targetObject: targetObj
    });
  } catch (err) {
    res.status(400).json({ error: 'Invalid JSON payload: ' + err.message });
  }
});

// Secure: Prevents prototype pollution by sanitizing keys or using native/safe merge
app.post('/api/dep/secure', (req, res) => {
  const payload = req.body.payload || '{}';
  try {
    const parsed = JSON.parse(payload);
    
    // Clear prototype pollution if present
    delete Object.prototype.polluted;

    // Secure recursive merge helper that ignores proto/constructor overrides
    const safeMerge = (target, source) => {
      for (const key in source) {
        if (key === '__proto__' || key === 'constructor') {
          continue; // Block prototype pollution vectors
        }
        if (typeof source[key] === 'object' && source[key] !== null) {
          if (!target[key]) target[key] = {};
          safeMerge(target[key], source[key]);
        } else {
          target[key] = source[key];
        }
      }
      return target;
    };

    const targetObj = {};
    safeMerge(targetObj, parsed);

    const isPolluted = ({}).polluted;

    res.json({
      message: isPolluted ? 'Successfully polluted Object.prototype!' : 'Secure merge completed.',
      objectPrototypePollutedValue: ({}).polluted,
      isPolluted: !!isPolluted,
      targetObject: targetObj
    });
  } catch (err) {
    res.status(400).json({ error: 'Invalid JSON payload: ' + err.message });
  }
});


// Start server
app.listen(PORT, () => {
  console.log(`===========================================================`);
  console.log(`VulnShield Sandbox running successfully at:`);
  console.log(`http://localhost:${PORT}`);
  console.log(`===========================================================`);
});
