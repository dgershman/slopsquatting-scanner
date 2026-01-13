const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

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

// API endpoint to scan code
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

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`Slopsquatting Scanner running at http://localhost:${PORT}`);
});
