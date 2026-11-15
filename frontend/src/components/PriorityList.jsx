import { SEVERITY_BADGE } from "../ui";

function Row({ label, children }) {
  if (!children) return null;
  return (
    <div>
      <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</div>
      <p className="mt-0.5 text-sm text-slate-700">{children}</p>
    </div>
  );
}

export default function PriorityList({ items }) {
  if (!items.length) {
    return <p className="text-sm text-slate-500">No issues found. Nothing urgent to fix.</p>;
  }
  return (
    <ol className="space-y-3">
      {items.map((f, i) => (
        <li key={f.id}>
          <details open={i === 0} className="group rounded-lg border border-slate-200 bg-white">
            <summary className="flex cursor-pointer list-none items-center gap-3 p-4">
              <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-slate-900 text-sm font-semibold text-white">
                {i + 1}
              </span>
              <div className="min-w-0 flex-1">
                <div className="font-semibold text-slate-900">{f.title}</div>
                <div className="text-xs text-slate-500">{f.impact_effort}</div>
              </div>
              <span className={`rounded-full border px-2.5 py-0.5 text-xs font-medium ${SEVERITY_BADGE[f.severity]}`}>
                {f.severity}
              </span>
            </summary>
            <div className="space-y-3 border-t border-slate-100 p-4">
              <Row label="What is wrong?">{f.description}</Row>
              <Row label="Why does it matter?">{f.business_impact}</Row>
              <Row label="How do I fix it?">{f.recommendation}</Row>
              <div className="flex gap-6 text-sm">
                <Row label="How urgent?">{f.severity}</Row>
                <Row label="How difficult?">{f.effort}</Row>
              </div>
            </div>
          </details>
        </li>
      ))}
    </ol>
  );
}
