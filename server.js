import app from './app.js';

const PORT = process.env.PORT || 3000;

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Solar API server running on http://127.0.0.1:${PORT}`);
});
