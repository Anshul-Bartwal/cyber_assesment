import { scoreColor } from "../ui";

export default function CategoryBars({ categories }) {
  return (
    <div className="space-y-4">
      {Object.entries(categories).map(([name, c]) => (
        <div key={name}>
          <div className="mb-1 flex justify-between text-sm">
            <span className="font-medium text-slate-700">{name}</span>
            {c.assessed ? (
              <span className="text-slate-600">
                {c.score}
                {c.issues > 0 && (
                  <span className="ml-2 text-xs text-slate-400">
                    {c.issues} issue{c.issues > 1 ? "s" : ""}
                  </span>
                )}
              </span>
            ) : (
              <span className="text-xs text-slate-400">Not assessed yet</span>
            )}
          </div>
          <div className="h-2.5 w-full rounded-full bg-slate-200">
            {c.assessed && (
              <div
                className={`h-2.5 rounded-full ${scoreColor(c.score).bar}`}
                style={{ width: `${c.score}%` }}
              />
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
