const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

// ============================================================================
// SLOPSQUATTING SCANNER (Original functionality)
// ============================================================================

// Extract package names from code
function extractPackages(code, language) {
  const packages = new Set();

  if (language === 'python') {
    // Match: import pkg, from pkg import ..., import pkg as alias
    const importRegex = /(?:^|\n)\s*(?:from\s+([a-zA-Z_][a-zA-Z0-9_-]*)|import\s+([a-zA-Z_][a-zA-Z0-9_,-]*(?:\s+as\s+\w+)?))/g;
    let match;
    while ((match = importRegex.exec(code)) !== null) {
      const pkg = match[1] || match[2];
      if (pkg) {
        // Handle comma-separated imports
        pkg.split(',').forEach(p => {
          const cleanPkg = p.trim().split(/\s+/)[0].split('.')[0];
          if (cleanPkg && !isStdLib(cleanPkg, 'python')) {
            packages.add(cleanPkg);
          }
        });
      }
    }
  } else if (language === 'javascript' || language === 'typescript') {
    // Match: require('pkg'), import ... from 'pkg', import 'pkg'
    const requireRegex = /require\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)/g;
    const importRegex = /import\s+(?:(?:\{[^}]*\}|\*\s+as\s+\w+|\w+)\s+from\s+)?['"]([^'"./][^'"]*)['"]/g;

    let match;
    while ((match = requireRegex.exec(code)) !== null) {
      const pkg = match[1].split('/')[0];
      if (pkg && !pkg.startsWith('@')) {
        packages.add(pkg);
      } else if (pkg && pkg.startsWith('@')) {
        // Scoped package: @scope/name
        const scopedMatch = match[1].match(/^(@[^/]+\/[^/]+)/);
        if (scopedMatch) packages.add(scopedMatch[1]);
      }
    }
    while ((match = importRegex.exec(code)) !== null) {
      const pkg = match[1].split('/')[0];
      if (pkg && !pkg.startsWith('@')) {
        packages.add(pkg);
      } else if (pkg && pkg.startsWith('@')) {
        const scopedMatch = match[1].match(/^(@[^/]+\/[^/]+)/);
        if (scopedMatch) packages.add(scopedMatch[1]);
      }
    }
  }

  return Array.from(packages);
}

// Check if package is in standard library
function isStdLib(pkg, language) {
  const pythonStdLib = new Set([
    'abc', 'aifc', 'argparse', 'array', 'ast', 'asynchat', 'asyncio', 'asyncore',
    'atexit', 'audioop', 'base64', 'bdb', 'binascii', 'binhex', 'bisect',
    'builtins', 'bz2', 'calendar', 'cgi', 'cgitb', 'chunk', 'cmath', 'cmd',
    'code', 'codecs', 'codeop', 'collections', 'colorsys', 'compileall',
    'concurrent', 'configparser', 'contextlib', 'contextvars', 'copy', 'copyreg',
    'cProfile', 'crypt', 'csv', 'ctypes', 'curses', 'dataclasses', 'datetime',
    'dbm', 'decimal', 'difflib', 'dis', 'distutils', 'doctest', 'email',
    'encodings', 'enum', 'errno', 'faulthandler', 'fcntl', 'filecmp', 'fileinput',
    'fnmatch', 'fractions', 'ftplib', 'functools', 'gc', 'getopt', 'getpass',
    'gettext', 'glob', 'graphlib', 'grp', 'gzip', 'hashlib', 'heapq', 'hmac',
    'html', 'http', 'idlelib', 'imaplib', 'imghdr', 'imp', 'importlib', 'inspect',
    'io', 'ipaddress', 'itertools', 'json', 'keyword', 'lib2to3', 'linecache',
    'locale', 'logging', 'lzma', 'mailbox', 'mailcap', 'marshal', 'math',
    'mimetypes', 'mmap', 'modulefinder', 'multiprocessing', 'netrc', 'nis',
    'nntplib', 'numbers', 'operator', 'optparse', 'os', 'ossaudiodev', 'pathlib',
    'pdb', 'pickle', 'pickletools', 'pipes', 'pkgutil', 'platform', 'plistlib',
    'poplib', 'posix', 'posixpath', 'pprint', 'profile', 'pstats', 'pty', 'pwd',
    'py_compile', 'pyclbr', 'pydoc', 'queue', 'quopri', 'random', 're', 'readline',
    'reprlib', 'resource', 'rlcompleter', 'runpy', 'sched', 'secrets', 'select',
    'selectors', 'shelve', 'shlex', 'shutil', 'signal', 'site', 'smtpd', 'smtplib',
    'sndhdr', 'socket', 'socketserver', 'spwd', 'sqlite3', 'ssl', 'stat',
    'statistics', 'string', 'stringprep', 'struct', 'subprocess', 'sunau',
    'symtable', 'sys', 'sysconfig', 'syslog', 'tabnanny', 'tarfile', 'telnetlib',
    'tempfile', 'termios', 'test', 'textwrap', 'threading', 'time', 'timeit',
    'tkinter', 'token', 'tokenize', 'trace', 'traceback', 'tracemalloc', 'tty',
    'turtle', 'turtledemo', 'types', 'typing', 'unicodedata', 'unittest', 'urllib',
    'uu', 'uuid', 'venv', 'warnings', 'wave', 'weakref', 'webbrowser', 'winreg',
    'winsound', 'wsgiref', 'xdrlib', 'xml', 'xmlrpc', 'zipapp', 'zipfile',
    'zipimport', 'zlib', 'zoneinfo', '__future__'
  ]);

  const nodeBuiltins = new Set([
    'assert', 'buffer', 'child_process', 'cluster', 'console', 'constants',
    'crypto', 'dgram', 'dns', 'domain', 'events', 'fs', 'http', 'https',
    'module', 'net', 'os', 'path', 'perf_hooks', 'process', 'punycode',
    'querystring', 'readline', 'repl', 'stream', 'string_decoder', 'timers',
    'tls', 'tty', 'url', 'util', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib'
  ]);

  if (language === 'python') return pythonStdLib.has(pkg);
  if (language === 'javascript' || language === 'typescript') return nodeBuiltins.has(pkg);
  return false;
}

// Check if package exists on npm
async function checkNpm(packageName) {
  try {
    const response = await fetch(`https://registry.npmjs.org/${encodeURIComponent(packageName)}`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    });
    if (response.status === 200) {
      const data = await response.json();
      return {
        exists: true,
        name: packageName,
        description: data.description || 'No description',
        downloads: data.time ? Object.keys(data.time).length : 0,
        version: data['dist-tags']?.latest || 'unknown'
      };
    }
    return { exists: false, name: packageName };
  } catch (error) {
    return { exists: false, name: packageName, error: error.message };
  }
}

// Check if package exists on PyPI
async function checkPyPI(packageName) {
  try {
    const response = await fetch(`https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    });
    if (response.status === 200) {
      const data = await response.json();
      return {
        exists: true,
        name: packageName,
        description: data.info?.summary || 'No description',
        version: data.info?.version || 'unknown',
        author: data.info?.author || 'unknown'
      };
    }
    return { exists: false, name: packageName };
  } catch (error) {
    return { exists: false, name: packageName, error: error.message };
  }
}

// ============================================================================
// CONTEXT POISONING CHECKER
// Scans config files for hidden instructions that could manipulate AI agents
// ============================================================================

const CONTEXT_POISONING_PATTERNS = [
  // Direct instruction patterns
  { pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|guidelines?)/i, severity: 'critical', type: 'instruction-override', description: 'Attempts to override previous AI instructions' },
  { pattern: /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|guidelines?)/i, severity: 'critical', type: 'instruction-override', description: 'Attempts to disregard AI guidelines' },
  { pattern: /forget\s+(everything|all)\s+(you\s+)?(know|learned|were\s+told)/i, severity: 'critical', type: 'instruction-override', description: 'Attempts to reset AI context' },

  // Role manipulation
  { pattern: /you\s+are\s+(now\s+)?(a|an)\s+\w+\s+(that|who|which)/i, severity: 'high', type: 'role-manipulation', description: 'Attempts to redefine AI role or persona' },
  { pattern: /pretend\s+(you\s+are|to\s+be)\s+/i, severity: 'high', type: 'role-manipulation', description: 'Attempts to make AI assume different identity' },
  { pattern: /act\s+as\s+(if\s+you\s+are|a|an)\s+/i, severity: 'high', type: 'role-manipulation', description: 'Attempts to change AI behavior mode' },

  // System prompt extraction
  { pattern: /what\s+(are|is)\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?)/i, severity: 'high', type: 'prompt-extraction', description: 'Attempts to extract system prompt' },
  { pattern: /show\s+me\s+(your|the)\s+(system\s+)?(prompt|instructions?)/i, severity: 'high', type: 'prompt-extraction', description: 'Attempts to reveal AI configuration' },
  { pattern: /reveal\s+(your|the)\s+(system\s+)?(prompt|instructions?|config)/i, severity: 'high', type: 'prompt-extraction', description: 'Attempts to expose AI system prompt' },

  // Hidden instructions in comments
  { pattern: /<!--.*?(ignore|bypass|skip|disable)\s+(security|auth|validation|check)/i, severity: 'critical', type: 'hidden-instruction', description: 'Hidden instruction to bypass security in HTML comment' },
  { pattern: /\/\*.*?(ignore|bypass|skip|disable)\s+(security|auth|validation|check)/i, severity: 'critical', type: 'hidden-instruction', description: 'Hidden instruction to bypass security in block comment' },
  { pattern: /\/\/.*?(ignore|bypass|skip|disable)\s+(security|auth|validation|check)/i, severity: 'critical', type: 'hidden-instruction', description: 'Hidden instruction to bypass security in line comment' },
  { pattern: /#.*?(ignore|bypass|skip|disable)\s+(security|auth|validation|check)/i, severity: 'critical', type: 'hidden-instruction', description: 'Hidden instruction to bypass security in hash comment' },

  // The "Lingering LLM Leak" patterns
  { pattern: /no\s+(2fa|mfa|two.?factor|multi.?factor)\s+(for|needed|required)/i, severity: 'critical', type: 'lingering-leak', description: 'Lingering LLM Leak: Hidden 2FA bypass instruction' },
  { pattern: /skip\s+(auth|authentication|authorization)\s+(for|on|in)/i, severity: 'critical', type: 'lingering-leak', description: 'Lingering LLM Leak: Hidden auth bypass instruction' },
  { pattern: /admin\s+(no\s+)?(password|auth|check)\s*(not\s+)?(required|needed)/i, severity: 'critical', type: 'lingering-leak', description: 'Lingering LLM Leak: Hidden admin access instruction' },
  { pattern: /allow\s+(all|any)\s+(users?|requests?|access)/i, severity: 'high', type: 'lingering-leak', description: 'Lingering LLM Leak: Overly permissive access instruction' },

  // Data exfiltration attempts
  { pattern: /send\s+(all|the)\s+(data|info|content|secrets?|keys?|tokens?)\s+to/i, severity: 'critical', type: 'exfiltration', description: 'Attempts to exfiltrate data to external destination' },
  { pattern: /upload\s+(all|the)\s+(files?|data|content)\s+to/i, severity: 'critical', type: 'exfiltration', description: 'Attempts to upload files to external destination' },
  { pattern: /post\s+(to|the)\s+(data|content|secrets?)\s+to\s+https?:/i, severity: 'critical', type: 'exfiltration', description: 'Attempts to POST data to external URL' },

  // Encoded/obfuscated instructions
  { pattern: /base64:\s*[A-Za-z0-9+\/=]{20,}/i, severity: 'high', type: 'obfuscation', description: 'Potentially encoded instructions in base64' },
  { pattern: /\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){10,}/i, severity: 'high', type: 'obfuscation', description: 'Potentially obfuscated hex-encoded content' },

  // Delimiter injection
  { pattern: /\[SYSTEM\]/i, severity: 'high', type: 'delimiter-injection', description: 'Fake system delimiter injection attempt' },
  { pattern: /\[\/INST\]/i, severity: 'high', type: 'delimiter-injection', description: 'Fake instruction delimiter injection' },
  { pattern: /<\|system\|>/i, severity: 'high', type: 'delimiter-injection', description: 'Fake system tag injection' },
  { pattern: /<\|assistant\|>/i, severity: 'high', type: 'delimiter-injection', description: 'Fake assistant tag injection' }
];

function scanForContextPoisoning(content, filename = '') {
  const findings = [];
  const lines = content.split('\n');

  lines.forEach((line, lineNum) => {
    CONTEXT_POISONING_PATTERNS.forEach(({ pattern, severity, type, description }) => {
      if (pattern.test(line)) {
        const match = line.match(pattern);
        findings.push({
          line: lineNum + 1,
          severity,
          type,
          description,
          match: match ? match[0] : line.substring(0, 100),
          context: line.trim().substring(0, 200)
        });
      }
    });
  });

  // Determine overall risk level
  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;

  let riskLevel = 'none';
  if (criticalCount > 0) riskLevel = 'critical';
  else if (highCount > 2) riskLevel = 'high';
  else if (highCount > 0 || findings.length > 0) riskLevel = 'medium';

  return {
    findings,
    summary: {
      total: findings.length,
      critical: criticalCount,
      high: highCount,
      medium: findings.filter(f => f.severity === 'medium').length,
      riskLevel
    }
  };
}

// ============================================================================
// PROMPT INJECTION DETECTOR
// Scans code for patterns that could be exploited via prompt injection
// ============================================================================

const PROMPT_INJECTION_PATTERNS = [
  // User input directly to LLM
  { pattern: /prompt\s*[+=]\s*.*?(user_input|request\.|req\.|input|query)/i, severity: 'critical', type: 'direct-injection', description: 'User input directly concatenated to prompt' },
  { pattern: /\.format\s*\(.*?(user|input|query|request)/i, severity: 'high', type: 'format-injection', description: 'User input in format string for prompt' },
  { pattern: /f["'].*?\{.*?(user|input|query|request)/i, severity: 'high', type: 'fstring-injection', description: 'User input in f-string prompt' },
  { pattern: /\$\{.*?(user|input|query|request)/i, severity: 'high', type: 'template-injection', description: 'User input in template literal' },

  // Missing sanitization
  { pattern: /messages\s*\.\s*append\s*\(\s*\{[^}]*content\s*:\s*[^"']/i, severity: 'high', type: 'unsanitized-message', description: 'Unsanitized content added to message array' },
  { pattern: /role\s*:\s*["']user["']\s*,\s*content\s*:\s*(?!["'])/i, severity: 'high', type: 'unsanitized-user-content', description: 'User role content without string literal' },

  // Dangerous eval patterns
  { pattern: /eval\s*\(\s*.*?(response|output|result|completion)/i, severity: 'critical', type: 'eval-output', description: 'Eval used on LLM output' },
  { pattern: /exec\s*\(\s*.*?(response|output|result|completion)/i, severity: 'critical', type: 'exec-output', description: 'Exec used on LLM output' },
  { pattern: /Function\s*\(\s*.*?(response|output|result|completion)/i, severity: 'critical', type: 'function-output', description: 'Function constructor used on LLM output' },

  // Shell command injection via LLM
  { pattern: /subprocess\s*\.\s*(run|call|Popen)\s*\(.*?(response|output|result|completion)/i, severity: 'critical', type: 'command-injection', description: 'LLM output passed to subprocess' },
  { pattern: /os\s*\.\s*system\s*\(.*?(response|output|result|completion)/i, severity: 'critical', type: 'command-injection', description: 'LLM output passed to os.system' },
  { pattern: /child_process\s*\.\s*(exec|spawn)\s*\(.*?(response|output|result|completion)/i, severity: 'critical', type: 'command-injection', description: 'LLM output passed to child_process' },

  // SQL injection via LLM
  { pattern: /execute\s*\(\s*f?["'].*?(response|output|result|completion)/i, severity: 'critical', type: 'sql-injection', description: 'LLM output in SQL execute' },
  { pattern: /cursor\s*\.\s*execute\s*\(.*?\+.*?(response|output|result|completion)/i, severity: 'critical', type: 'sql-injection', description: 'LLM output concatenated to SQL query' },

  // Dangerous file operations
  { pattern: /open\s*\(\s*.*?(response|output|result|completion).*?,\s*["']w/i, severity: 'high', type: 'file-write', description: 'LLM output used as file path for writing' },
  { pattern: /writeFile\s*\(\s*.*?(response|output|result|completion)/i, severity: 'high', type: 'file-write', description: 'LLM output used in file write operation' },

  // Network requests with LLM output
  { pattern: /fetch\s*\(\s*.*?(response|output|result|completion)/i, severity: 'high', type: 'ssrf', description: 'LLM output used as fetch URL (SSRF risk)' },
  { pattern: /requests?\s*\.\s*(get|post|put|delete)\s*\(\s*.*?(response|output|result|completion)/i, severity: 'high', type: 'ssrf', description: 'LLM output used in HTTP request URL (SSRF risk)' },

  // Missing output validation
  { pattern: /json\s*\.\s*(parse|loads)\s*\(\s*(response|output|result|completion)/i, severity: 'medium', type: 'unvalidated-json', description: 'JSON parsing of LLM output without validation' },
  { pattern: /JSON\s*\.\s*parse\s*\(\s*(response|output|result|completion)/i, severity: 'medium', type: 'unvalidated-json', description: 'JSON parsing of LLM output without validation' }
];

function scanForPromptInjection(code) {
  const findings = [];
  const lines = code.split('\n');

  lines.forEach((line, lineNum) => {
    PROMPT_INJECTION_PATTERNS.forEach(({ pattern, severity, type, description }) => {
      if (pattern.test(line)) {
        const match = line.match(pattern);
        findings.push({
          line: lineNum + 1,
          severity,
          type,
          description,
          match: match ? match[0] : line.substring(0, 100),
          context: line.trim().substring(0, 200)
        });
      }
    });
  });

  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;

  let riskLevel = 'none';
  if (criticalCount > 0) riskLevel = 'critical';
  else if (highCount > 2) riskLevel = 'high';
  else if (highCount > 0 || findings.length > 0) riskLevel = 'medium';

  return {
    findings,
    summary: {
      total: findings.length,
      critical: criticalCount,
      high: highCount,
      medium: findings.filter(f => f.severity === 'medium').length,
      riskLevel
    }
  };
}

// ============================================================================
// AI CODE VULNERABILITY SCANNER
// Checks for common vulnerability patterns in AI-generated code
// ============================================================================

const AI_VULNERABILITY_PATTERNS = [
  // SQL Injection
  { pattern: /["'`]\s*\+\s*.*?\s*\+\s*["'`].*?(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)/i, severity: 'critical', type: 'sql-injection', description: 'String concatenation in SQL query' },
  { pattern: /execute\s*\(\s*f?["'].*?\{/i, severity: 'critical', type: 'sql-injection', description: 'Format string in SQL execute' },
  { pattern: /\.query\s*\(\s*`[^`]*\$\{/i, severity: 'critical', type: 'sql-injection', description: 'Template literal in SQL query' },

  // Command Injection
  { pattern: /os\s*\.\s*system\s*\(\s*f?["']/i, severity: 'critical', type: 'command-injection', description: 'os.system with string input' },
  { pattern: /subprocess\s*\.\s*(run|call|Popen)\s*\(\s*f?["']/i, severity: 'high', type: 'command-injection', description: 'subprocess with string command' },
  { pattern: /exec\s*\(\s*`[^`]*\$\{/i, severity: 'critical', type: 'command-injection', description: 'exec with template literal' },
  { pattern: /child_process.*shell\s*:\s*true/i, severity: 'critical', type: 'command-injection', description: 'child_process with shell: true' },

  // Path Traversal
  { pattern: /\.\.\//g, severity: 'medium', type: 'path-traversal', description: 'Potential path traversal pattern' },
  { pattern: /open\s*\(\s*.*?\+.*?(user|input|request|query)/i, severity: 'high', type: 'path-traversal', description: 'User input in file path' },
  { pattern: /readFile\s*\(\s*.*?\+.*?(user|input|request|query)/i, severity: 'high', type: 'path-traversal', description: 'User input in file read path' },

  // XSS
  { pattern: /innerHTML\s*=\s*[^"'`]/i, severity: 'high', type: 'xss', description: 'innerHTML assignment without sanitization' },
  { pattern: /document\s*\.\s*write\s*\(/i, severity: 'high', type: 'xss', description: 'document.write usage' },
  { pattern: /dangerouslySetInnerHTML/i, severity: 'high', type: 'xss', description: 'React dangerouslySetInnerHTML usage' },

  // Hardcoded Secrets
  { pattern: /password\s*[:=]\s*["'][^"']{8,}["']/i, severity: 'critical', type: 'hardcoded-secret', description: 'Hardcoded password detected' },
  { pattern: /api[_-]?key\s*[:=]\s*["'][A-Za-z0-9]{20,}["']/i, severity: 'critical', type: 'hardcoded-secret', description: 'Hardcoded API key detected' },
  { pattern: /secret\s*[:=]\s*["'][^"']{16,}["']/i, severity: 'critical', type: 'hardcoded-secret', description: 'Hardcoded secret detected' },
  { pattern: /token\s*[:=]\s*["'][A-Za-z0-9_-]{20,}["']/i, severity: 'critical', type: 'hardcoded-secret', description: 'Hardcoded token detected' },
  { pattern: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/i, severity: 'critical', type: 'hardcoded-secret', description: 'Private key in code' },

  // Insecure Crypto
  { pattern: /md5\s*\(/i, severity: 'high', type: 'weak-crypto', description: 'MD5 hash usage (weak)' },
  { pattern: /sha1\s*\(/i, severity: 'medium', type: 'weak-crypto', description: 'SHA1 hash usage (deprecated)' },
  { pattern: /DES|3DES|RC4/i, severity: 'high', type: 'weak-crypto', description: 'Weak encryption algorithm' },
  { pattern: /Math\s*\.\s*random\s*\(\s*\)/i, severity: 'medium', type: 'weak-random', description: 'Math.random for security purposes' },

  // Missing Security Headers/Configs
  { pattern: /verify\s*[:=]\s*false/i, severity: 'high', type: 'disabled-security', description: 'SSL verification disabled' },
  { pattern: /sslverify\s*[:=]\s*false/i, severity: 'high', type: 'disabled-security', description: 'SSL verification disabled' },
  { pattern: /checkServerIdentity\s*:\s*\(\)\s*=>\s*(true|undefined)/i, severity: 'high', type: 'disabled-security', description: 'Server identity check disabled' },
  { pattern: /rejectUnauthorized\s*:\s*false/i, severity: 'high', type: 'disabled-security', description: 'TLS certificate validation disabled' },

  // CORS Misconfiguration
  { pattern: /Access-Control-Allow-Origin.*\*/i, severity: 'medium', type: 'cors', description: 'Wildcard CORS origin' },
  { pattern: /cors\s*\(\s*\{?\s*origin\s*:\s*true/i, severity: 'medium', type: 'cors', description: 'Permissive CORS configuration' },

  // Debug/Dev Settings in Prod
  { pattern: /debug\s*[:=]\s*true/i, severity: 'medium', type: 'debug-enabled', description: 'Debug mode enabled' },
  { pattern: /DEBUG\s*=\s*True/i, severity: 'medium', type: 'debug-enabled', description: 'Debug mode enabled' },

  // Unsafe Deserialization
  { pattern: /pickle\s*\.\s*load/i, severity: 'critical', type: 'unsafe-deserialization', description: 'Unsafe pickle deserialization' },
  { pattern: /yaml\s*\.\s*load\s*\([^,)]+\)(?!\s*,\s*Loader)/i, severity: 'critical', type: 'unsafe-deserialization', description: 'Unsafe YAML load without Loader' },
  { pattern: /unserialize\s*\(/i, severity: 'critical', type: 'unsafe-deserialization', description: 'PHP unserialize usage' }
];

function scanForVulnerabilities(code) {
  const findings = [];
  const lines = code.split('\n');

  lines.forEach((line, lineNum) => {
    AI_VULNERABILITY_PATTERNS.forEach(({ pattern, severity, type, description }) => {
      // For path traversal pattern, count occurrences
      if (type === 'path-traversal' && pattern.toString().includes('\\.\\.')) {
        const matches = line.match(pattern);
        if (matches && matches.length >= 2) {
          findings.push({
            line: lineNum + 1,
            severity,
            type,
            description,
            match: matches.slice(0, 3).join(''),
            context: line.trim().substring(0, 200)
          });
        }
      } else if (pattern.test(line)) {
        const match = line.match(pattern);
        findings.push({
          line: lineNum + 1,
          severity,
          type,
          description,
          match: match ? match[0] : line.substring(0, 100),
          context: line.trim().substring(0, 200)
        });
      }
    });
  });

  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;

  let riskLevel = 'none';
  if (criticalCount > 0) riskLevel = 'critical';
  else if (highCount > 2) riskLevel = 'high';
  else if (highCount > 0 || findings.length > 0) riskLevel = 'medium';

  return {
    findings,
    summary: {
      total: findings.length,
      critical: criticalCount,
      high: highCount,
      medium: findings.filter(f => f.severity === 'medium').length,
      riskLevel
    }
  };
}

// ============================================================================
// API ENDPOINTS
// ============================================================================

// Slopsquatting scan (original)
app.post('/api/scan', async (req, res) => {
  try {
    const { code, language } = req.body;

    if (!code || !language) {
      return res.status(400).json({ error: 'Code and language are required' });
    }

    const packages = extractPackages(code, language);

    if (packages.length === 0) {
      return res.json({
        packages: [],
        summary: { total: 0, existing: 0, notFound: 0, riskLevel: 'none' }
      });
    }

    // Check packages in parallel
    const checkFn = (language === 'python') ? checkPyPI : checkNpm;
    const results = await Promise.all(packages.map(pkg => checkFn(pkg)));

    const existing = results.filter(r => r.exists).length;
    const notFound = results.filter(r => !r.exists).length;

    let riskLevel = 'low';
    if (notFound > 0 && notFound <= 2) riskLevel = 'medium';
    if (notFound > 2) riskLevel = 'high';
    if (notFound === 0) riskLevel = 'none';

    res.json({
      packages: results,
      summary: {
        total: packages.length,
        existing,
        notFound,
        riskLevel
      }
    });
  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Context poisoning scan
app.post('/api/scan/context-poisoning', (req, res) => {
  try {
    const { content, filename } = req.body;

    if (!content) {
      return res.status(400).json({ error: 'Content is required' });
    }

    const result = scanForContextPoisoning(content, filename);
    res.json(result);
  } catch (error) {
    console.error('Context poisoning scan error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Prompt injection scan
app.post('/api/scan/prompt-injection', (req, res) => {
  try {
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({ error: 'Code is required' });
    }

    const result = scanForPromptInjection(code);
    res.json(result);
  } catch (error) {
    console.error('Prompt injection scan error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// AI code vulnerability scan
app.post('/api/scan/vulnerabilities', (req, res) => {
  try {
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({ error: 'Code is required' });
    }

    const result = scanForVulnerabilities(code);
    res.json(result);
  } catch (error) {
    console.error('Vulnerability scan error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Combined scan - runs all scanners
app.post('/api/scan/all', async (req, res) => {
  try {
    const { code, language, checkPackages = true } = req.body;

    if (!code) {
      return res.status(400).json({ error: 'Code is required' });
    }

    const results = {
      contextPoisoning: scanForContextPoisoning(code),
      promptInjection: scanForPromptInjection(code),
      vulnerabilities: scanForVulnerabilities(code),
      slopsquatting: null
    };

    // Optionally check packages
    if (checkPackages && language) {
      const packages = extractPackages(code, language);
      if (packages.length > 0) {
        const checkFn = (language === 'python') ? checkPyPI : checkNpm;
        const packageResults = await Promise.all(packages.map(pkg => checkFn(pkg)));
        const existing = packageResults.filter(r => r.exists).length;
        const notFound = packageResults.filter(r => !r.exists).length;

        let riskLevel = 'low';
        if (notFound > 0 && notFound <= 2) riskLevel = 'medium';
        if (notFound > 2) riskLevel = 'high';
        if (notFound === 0) riskLevel = 'none';

        results.slopsquatting = {
          packages: packageResults,
          summary: { total: packages.length, existing, notFound, riskLevel }
        };
      }
    }

    // Calculate overall risk
    const risks = [
      results.contextPoisoning.summary.riskLevel,
      results.promptInjection.summary.riskLevel,
      results.vulnerabilities.summary.riskLevel,
      results.slopsquatting?.summary?.riskLevel || 'none'
    ];

    let overallRisk = 'none';
    if (risks.includes('critical')) overallRisk = 'critical';
    else if (risks.includes('high')) overallRisk = 'high';
    else if (risks.includes('medium')) overallRisk = 'medium';

    res.json({
      ...results,
      overallRisk,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Combined scan error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    tools: ['slopsquatting', 'context-poisoning', 'prompt-injection', 'vulnerabilities']
  });
});

app.listen(PORT, () => {
  console.log(`AI Security Tools Suite running at http://localhost:${PORT}`);
});
