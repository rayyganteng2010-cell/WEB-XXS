const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();

app.use(cors());
app.use(express.json());

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// API endpoints - now handled by separate files in /api
app.get('/api/test', (req, res) => {
  res.json({ status: 'API is working', version: '1.0.0' });
});

// Health check endpoint for Vercel
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Fallback route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 XSS Hunter running on port ${PORT}`);
  console.log(`📡 API endpoints available at /api/scan, /api/crawl, /api/report`);
});
