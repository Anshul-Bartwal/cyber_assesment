// All communication with the FastAPI backend lives here.
const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

async function request(path, options) {
  let res;
  try {
    res = await fetch(`${API_URL}${path}`, options);
  } catch {
    throw new Error(
      "Can't reach the CyberCheck API. Is the backend running on port 8000?"
    );
  }

  const data = await res.json().catch(() => null);
  if (!res.ok) {
    // 400/404 errors carry a readable message in `detail`.
    const message =
      typeof data?.detail === "string" ? data.detail : "Something went wrong.";
    throw new Error(message);
  }
  return data;
}

function postJson(body) {
  return {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}

export function scanDomain(domain) {
  return request("/scan", postJson({ domain }));
}

export async function getQuestions() {
  const data = await request("/questionnaire");
  return data.questions;
}

// Combines questionnaire answers with the saved scan (no re-scan needed).
export function submitAnswers(scanId, answers) {
  return request(`/scan/${scanId}/answers`, postJson({ answers }));
}
