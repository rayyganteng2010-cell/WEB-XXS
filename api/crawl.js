const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');

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
    const { url, maxPages = 50, depth = 3 } = req.body;
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    const baseUrl = new URL(url);
    const visited = new Set();
    const toVisit = [{ url, depth: 0 }];
    const allLinks = new Set([url]);
    const endpoints = new Set();
    const parameters = new Set();

    while (toVisit.length > 0 && visited.size < maxPages) {
      const { url: currentUrl, depth: currentDepth } = toVisit.shift();
      
      if (visited.has(currentUrl) || currentDepth > depth) {
        continue;
      }

      visited.add(currentUrl);
      
      try {
        const response = await axios.get(currentUrl, {
          timeout: 5000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
          }
        });

        const $ = cheerio.load(response.data);
        
        // Extract all links
        $('a[href]').each((i, element) => {
          let href = $(element).attr('href');
          
          if (!href || href.startsWith('javascript:') || href.startsWith('mailto:')) {
            return;
          }

          try {
            // Convert relative URLs to absolute
            const absoluteUrl = new URL(href, currentUrl).href;
            
            // Only follow same-domain links
            const linkUrl = new URL(absoluteUrl);
            if (linkUrl.hostname === baseUrl.hostname) {
              if (!visited.has(absoluteUrl) && !toVisit.some(v => v.url === absoluteUrl)) {
                toVisit.push({ url: absoluteUrl, depth: currentDepth + 1 });
              }
              allLinks.add(absoluteUrl);
              
              // Extract endpoints and parameters
              endpoints.add(linkUrl.pathname);
              linkUrl.searchParams.forEach((value, key) => {
                parameters.add(`${key}=${value}`);
              });
            }
          } catch (error) {
            // Invalid URL, skip
          }
        });

        // Extract form endpoints
        $('form[action]').each((i, form) => {
          let action = $(form).attr('action');
          const method = $(form).attr('method') || 'GET';
          
          try {
            const actionUrl = new URL(action, currentUrl);
            if (actionUrl.hostname === baseUrl.hostname) {
              endpoints.add(actionUrl.pathname);
              endpoints.add(`[${method}] ${actionUrl.pathname}`);
            }
          } catch (error) {
            // Invalid URL, skip
          }
        });

        // Extract script and link resources
        $('script[src], link[href], img[src], iframe[src]').each((i, element) => {
          const src = $(element).attr('src') || $(element).attr('href');
          if (src && !src.startsWith('data:')) {
            try {
              const resourceUrl = new URL(src, currentUrl);
              if (resourceUrl.hostname === baseUrl.hostname) {
                allLinks.add(resourceUrl.href);
              }
            } catch (error) {
              // Invalid URL, skip
            }
          }
        });

      } catch (error) {
        console.error(`Error crawling ${currentUrl}:`, error.message);
      }
    }

    // Analyze for potential vulnerabilities
    const analysis = {
      totalLinks: allLinks.size,
      uniqueEndpoints: endpoints.size,
      parametersFound: parameters.size,
      potentialVulnerabilities: []
    };

    // Check for common vulnerable patterns
    Array.from(endpoints).forEach(endpoint => {
      if (endpoint.includes('admin') || endpoint.includes('login') || endpoint.includes('config')) {
        analysis.potentialVulnerabilities.push({
          type: 'Sensitive Endpoint',
          endpoint,
          severity: 'high',
          description: 'Potential admin or sensitive page'
        });
      }
      
      if (endpoint.includes('.php') || endpoint.includes('.asp') || endpoint.includes('.aspx')) {
        analysis.potentialVulnerabilities.push({
          type: 'Dynamic Page',
          endpoint,
          severity: 'medium',
          description: 'Dynamic server-side page detected'
        });
      }
    });

    Array.from(parameters).forEach(param => {
      if (param.includes('id=') || param.includes('user=') || param.includes('admin=')) {
        analysis.potentialVulnerabilities.push({
          type: 'Sensitive Parameter',
          parameter: param,
          severity: 'medium',
          description: 'Parameter that might be vulnerable to injection'
        });
      }
    });

    const result = {
      url,
      crawledPages: visited.size,
      links: Array.from(allLinks).slice(0, 100), // Limit response size
      endpoints: Array.from(endpoints),
      parameters: Array.from(parameters),
      analysis,
      crawlDate: new Date().toISOString()
    };

    res.status(200).json(result);

  } catch (error) {
    console.error('Crawl error:', error);
    res.status(500).json({ 
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
};
