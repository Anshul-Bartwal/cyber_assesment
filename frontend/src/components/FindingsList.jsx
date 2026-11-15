import { useState } from "react";
import { SEVERITY_BADGE } from "../ui";

const TABS = [
  { key: "ISSUE", label: "Issues" },
  { key: "PASS", label: "Passed" },
  { key: "ERROR", label: "Could not check" },
];

export default function FindingsList({ findings }) {
  const [tab, setTab] = useState("ISSUE");
  const shown = findings.filter((f) => f.status === tab);

  return (
    <div>
      <div className="mb-4 flex gap-2">
        {TABS.map((t) => {
          const count = findings.filter((f) => f.status === t.key).length;
          const active = tab === t.key;
          return (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`rounded-full px-4 py-1.5 text-sm font-medium ${
                active ? "bg-slate-900 text-white" : "bg-slate-100 text-slate-600 hover:bg-slate-200"
              }`}
            >
              {t.label} ({count})
            </button>
          );
        })}
      </div>

      {shown.length === 0 && <p className="text-sm text-slate-500">Nothing here.</p>}

      <ul className="space-y-2">
        {shown.map((f) => (
          <li key={f.id + f.title} className="rounded-lg border border-slate-200 bg-white p-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="font-medium text-slate-900">{f.title}</div>
                <div className="text-xs text-slate-400">{f.category}</div>
              </div>
              {f.status === "ISSUE" && (
                <span className={`shrink-0 rounded-full border px-2.5 py-0.5 text-xs font-medium ${SEVERITY_BADGE[f.severity]}`}>
                  {f.severity}
                </span>
              )}
            </div>
            <p className="mt-2 text-sm text-slate-600">{f.description}</p>
            {f.status === "ISSUE" && f.recommendation && (
              <p className="mt-2 text-sm text-slate-700">
                <span className="font-semibold">Fix: </span>
                {f.recommendation}
              </p>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
