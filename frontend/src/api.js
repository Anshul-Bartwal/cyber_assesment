// All communication with the FastAPI backend lives here.
const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

export async function scanDomain(domain) {
  let res;
  try {
    res = await fetch(`${API_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    });
  } catch {
    throw new Error(
      "Can't reach the CyberCheck API. Is the backend running on port 8000?"
    );
  }

  const data = await res.json().catch(() => null);
  if (!res.ok) {
    // 400 errors carry a readable message in `detail` (e.g. invalid domain).
    const message =
      typeof data?.detail === "string" ? data.detail : "The scan failed.";
    throw new Error(message);
  }
  return data;
}
