# Slopsquatting Scanner

A security awareness tool that scans AI-generated code for potentially hallucinated package names.

## What is Slopsquatting?

Slopsquatting exploits AI code assistants' tendency to hallucinate non-existent package names. Attackers register these fake package names on npm/PyPI with malicious code. When developers copy AI-generated code, they unknowingly install the malicious packages.

### Key Statistics
- ~20% of AI code samples contain hallucinated packages
- 58% of hallucinated names recur across multiple prompts
- GPT-4 Turbo: 3.59% hallucination rate
- CodeLlama: >33% hallucination rate

## Features

- Scans JavaScript/TypeScript code for npm packages
- Scans Python code for PyPI packages
- Checks packages against live registries
- Visual risk assessment
- Educational content about slopsquatting attacks

## Quick Start

```bash
# Install dependencies
npm install

# Start the server
npm start

# Open http://localhost:3000
```

## How It Works

1. Paste AI-generated code into the scanner
2. Select the programming language (JavaScript or Python)
3. The tool extracts all import/require statements
4. Each package is verified against npm or PyPI
5. Results show which packages exist vs. potentially hallucinated

## API Endpoints

### POST /api/scan
Scan code for hallucinated packages.

**Request:**
```json
{
  "code": "import express from 'express';",
  "language": "javascript"
}
```

**Response:**
```json
{
  "packages": [
    { "name": "express", "exists": true, "description": "..." }
  ],
  "summary": {
    "total": 1,
    "existing": 1,
    "notFound": 0,
    "riskLevel": "none"
  }
}
```

## References

- [Trend Micro: Slopsquatting](https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/slopsquatting-when-ai-agents-hallucinate-malicious-packages)
- [BleepingComputer: AI Hallucinated Code Dependencies](https://www.bleepingcomputer.com/news/security/ai-hallucinated-code-dependencies-become-new-supply-chain-risk/)
- [Snyk: Package Hallucinations](https://snyk.io/articles/package-hallucinations/)

## License

MIT - Built by [beforethecommit](https://beforethecommit.com) for security awareness.
