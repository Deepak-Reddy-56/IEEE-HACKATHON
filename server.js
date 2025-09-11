// server.js (Node.js/Express example)
const express = require('express');
const fetch = require('node-fetch');

app.post('/api/analyze', async (req, res) => {
  const { message } = req.body;
  const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key=${process.env.GEMINI_API_KEY}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(message)
  });
  res.json(await response.json());
});