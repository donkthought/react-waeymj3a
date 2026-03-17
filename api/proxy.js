export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).end();

  // Debug — remove this block once working
  const key = process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_KEY;
  if (!key) return res.status(500).json({ error: { message: "NO_KEY_FOUND" } });
  if (!key.startsWith("sk-ant-")) return res.status(500).json({ error: { message: "BAD_KEY_FORMAT: " + key.slice(0, 8) } });

  // Optional: lock to your domain in production
  // const origin = req.headers.origin;
  // if (origin !== "https://truthilizer.com") return res.status(403).end();

  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify(req.body),
    });

    const data = await response.json();
    res.status(response.status).json(data);
  } catch (err) {
    res.status(500).json({ error: { message: err.message } });
  }
}
