module.exports = async (req, res) => {
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
    const { scanResults, format = 'html' } = req.body;
    
    if (!scanResults) {
      return res.status(400).json({ error: 'Scan results are required' });
    }

    let report;
    
    if (format === 'html') {
      report = generateHTMLReport(scanResults);
    } else if (format === 'text') {
      report = generateTextReport(scanResults);
    } else if (format === 'json') {
      report = JSON.stringify(scanResults, null, 2);
    } else {
      report = generateHTMLReport(scanResults);
    }

    res.setHeader('Content-Type', format === 'json' ? 'application/json' : 'text/html');
    res.status(200).send(report);

  } catch (error) {
    console.error('Report generation error:', error);
    res.status(500).json({ error: error.message });
  }
};

function generateHTMLReport(data) {
  return `
<!DOCTYPE html>
<html>
<head>
    <title>XSS Scan Report - ${data.url}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .report { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .vulnerability { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .critical { background: #f8d7da; border-left-color: #dc3545; }
        .high { background: #fff3cd; border-left-color: #ffc107; }
        .medium { background: #d1ecf1; border-left-color: #17a2b8; }
        .low { background: #d4edda; border-left-color: #28a745; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }
        .stat-box { background: #e9ecef; padding: 20px; border-radius: 5px; text-align: center; }
        .stat-value { font-size: 24px; font-weight: bold; color: #333; }
        .stat-label { color: #666; font-size: 14px; }
        code { background: #eee; padding: 2px 5px; border-radius: 3px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="report">
        <h1>🔍 XSS Vulnerability Scan Report</h1>
        <p><strong>Target URL:</strong> ${data.url}</p>
        <p><strong>Scan Date:</strong> ${new Date(data.timestamp).toLocaleString()}</p>
        
        <div class="stats">
            <div class="stat-box">
                <div class="stat-value">${data.stats?.totalVulnerabilities || 0}</div>
                <div class="stat-label">Total Vulnerabilities</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">${data.stats?.criticalCount || 0}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">${data.stats?.xssCount || 0}</div>
                <div class="stat-label">XSS Vulnerabilities</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">${data.stats?.sqliCount || 0}</div>
                <div class="stat-label">SQL Injection</div>
            </div>
        </div>
        
        <h2>📊 Security Headers</h2>
        <table>
            <tr>
                <th>Header</th>
                <th>Status</th>
            </tr>
            ${Object.entries(data.securityHeaders || {}).map(([header, status]) => `
                <tr>
                    <td>${header}</td>
                    <td><span style="color: ${status === 'MISSING' ? 'red' : 'green'}">${status}</span></td>
                </tr>
            `).join('')}
        </table>
        
        <h2>⚠️ Detected Vulnerabilities</h2>
        ${(data.vulnerabilities || []).map(vuln => `
            <div class="vulnerability ${vuln.severity}">
                <h3>${vuln.type} - ${vuln.severity.toUpperCase()}</h3>
                <p><strong>Location:</strong> ${vuln.location}</p>
                <p><strong>Payload:</strong> <code>${vuln.payload}</code></p>
                <p><strong>Exploitation:</strong> ${vuln.exploitation || 'N/A'}</p>
                ${vuln.context ? `<p><strong>Context:</strong> ${vuln.context}</p>` : ''}
            </div>
        `).join('')}
        
        <h2>📝 Forms Detected</h2>
        <table>
            <tr>
                <th>Form ID</th>
                <th>Action</th>
                <th>Method</th>
                <th>Inputs</th>
            </tr>
            ${(data.formsDetected || []).map(form => `
                <tr>
                    <td>${form.id}</td>
                    <td>${form.action}</td>
                    <td>${form.method}</td>
                    <td>${form.inputs.map(i => i.name).join(', ')}</td>
                </tr>
            `).join('')}
        </table>
        
        <h2>📋 Scan Summary</h2>
        <p>Total payloads tested: ${data.payloadsTested?.length || 0}</p>
        <p>Vulnerable payloads: ${data.vulnerabilities?.length || 0}</p>
        <p>Success rate: ${((data.vulnerabilities?.length || 0) / (data.payloadsTested?.length || 1) * 100).toFixed(2)}%</p>
        
        <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;">
            <p>Generated by Oxylus XSS Hunter</p>
            <p>⚠️ This report is for authorized security testing only</p>
        </footer>
    </div>
</body>
</html>
  `;
}

function generateTextReport(data) {
  let report = `XSS VULNERABILITY SCAN REPORT\n`;
  report += `================================\n\n`;
  report += `Target URL: ${data.url}\n`;
  report += `Scan Date: ${new Date(data.timestamp).toLocaleString()}\n\n`;
  
  report += `SUMMARY\n`;
  report += `-------\n`;
  report += `Total Vulnerabilities: ${data.stats?.totalVulnerabilities || 0}\n`;
  report += `Critical: ${data.stats?.criticalCount || 0}\n`;
  report += `XSS: ${data.stats?.xssCount || 0}\n`;
  report += `SQL Injection: ${data.stats?.sqliCount || 0}\n\n`;
  
  report += `VULNERABILITIES\n`;
  report += `--------------\n`;
  (data.vulnerabilities || []).forEach((vuln, i) => {
    report += `${i + 1}. [${vuln.severity.toUpperCase()}] ${vuln.type}\n`;
    report += `   Payload: ${vuln.payload}\n`;
    report += `   Location: ${vuln.location}\n`;
    if (vuln.exploitation) {
      report += `   Exploitation: ${vuln.exploitation}\n`;
    }
    report += `\n`;
  });
  
  report += `SECURITY HEADERS\n`;
  report += `----------------\n`;
  Object.entries(data.securityHeaders || {}).forEach(([header, status]) => {
    report += `${header}: ${status}\n`;
  });
  
  return report;
                         }
