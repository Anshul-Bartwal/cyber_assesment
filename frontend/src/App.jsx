import { useEffect, useState } from "react";
import { scanDomain } from "./api";
import ScoreRing from "./components/ScoreRing";
import CategoryBars from "./components/CategoryBars";
import PriorityList from "./components/PriorityList";
import FindingsList from "./components/FindingsList";

const STEPS = [
  "Checking HTTPS and security headers…",
  "Inspecting the TLS certificate…",
  "Looking up email records (SPF, DMARC)…",
  "Checking for exposed services…",
  "Calculating your score…",
];

function Card({ title, children }) {
  return (
    <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      {title && <h2 className="mb-4 text-lg font-semibold text-slate-900">{title}</h2>}
      {children}
    </section>
  );
}

export default function App() {
  const [domain, setDomain] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [stepIndex, setStepIndex] = useState(0);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  // The API answers in one go, so rotate friendly status messages while
  // we wait. (Real streaming progress is a later polish item.)
  useEffect(() => {
    if (!loading) return;
    setStepIndex(0);
    const id = setInterval(
      () => setStepIndex((i) => Math.min(i + 1, STEPS.length - 1)),
      4000
    );
    return () => clearInterval(id);
  }, [loading]);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setResult(null);
    setLoading(true);
    try {
      setResult(await scanDomain(domain.trim()));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  const score = result?.score;

  return (
    <div className="mx-auto max-w-3xl px-4 py-10">
      <header className="mb-8 text-center">
        <h1 className="text-3xl font-bold tracking-tight text-slate-900">CyberCheck</h1>
        <p className="mt-1 text-slate-500">
          Affordable cybersecurity assessment for small businesses
        </p>
      </header>

      <Card>
        <form onSubmit={handleSubmit} className="space-y-4">
          <label className="block text-sm font-medium text-slate-700">
            Enter your business domain
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example-business.com"
              disabled={loading}
              className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-slate-900 focus:border-slate-500 focus:outline-none"
            />
          </label>
          <label className="flex items-start gap-2 text-sm text-slate-600">
            <input
              type="checkbox"
              checked={authorized}
              onChange={(e) => setAuthorized(e.target.checked)}
              disabled={loading}
              className="mt-0.5"
            />
            I own this domain or have explicit authorization to assess it.
          </label>
          <button
            type="submit"
            disabled={loading || !authorized || domain.trim().length < 3}
            className="w-full rounded-lg bg-slate-900 px-4 py-2.5 font-medium text-white hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {loading ? "Assessing…" : "Start assessment"}
          </button>
        </form>
      </Card>

      {loading && (
        <p className="mt-6 text-center text-sm text-slate-500" role="status">
          {STEPS[stepIndex]} <span className="text-slate-400">(this can take up to 30 seconds)</span>
        </p>
      )}

      {error && (
        <div className="mt-6 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800" role="alert">
          {error}
        </div>
      )}

      {result && (
        <div className="mt-6 space-y-6">
          <Card>
            <div className="flex flex-col items-center gap-6 sm:flex-row">
              {score.overall !== null ? (
                <ScoreRing score={score.overall} />
              ) : (
                <p className="text-slate-500">Not enough data to calculate a score.</p>
              )}
              <div className="flex-1">
                <div className="text-sm text-slate-500">Security score for</div>
                <div className="mb-3 text-xl font-semibold text-slate-900">{result.domain}</div>
                {score.coverage_percent < 100 && (
                  <p className="rounded-md bg-amber-50 p-3 text-sm text-amber-800">
                    This score covers {score.coverage_percent}% of the full assessment.
                    Authentication and business practices will be included once the
                    questionnaire is completed.
                  </p>
                )}
                {score.checks_that_could_not_run > 0 && (
                  <p className="mt-2 text-xs text-slate-500">
                    {score.checks_that_could_not_run} check(s) could not run, so the score may be incomplete.
                  </p>
                )}
              </div>
            </div>
          </Card>

          <Card title="Category scores">
            <CategoryBars categories={score.categories} />
          </Card>

          <Card title="What to fix first">
            <PriorityList items={result.top_priorities} />
          </Card>

          <Card title="All findings">
            <FindingsList findings={result.findings} />
          </Card>

          <p className="text-center text-xs text-slate-400">
            Scanned {new Date(result.scanned_at).toLocaleString()}. This is a first-level
            automated assessment, not a replacement for a professional penetration test.
          </p>
        </div>
      )}
    </div>
  );
}
