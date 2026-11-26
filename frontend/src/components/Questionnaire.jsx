const OPTIONS = [
  { value: "yes", label: "Yes" },
  { value: "no", label: "No" },
  { value: "unsure", label: "Not sure" },
];

// A follow-up question only appears once its parent is answered "yes".
function isVisible(q, answers) {
  return !q.depends_on || answers[q.depends_on] === "yes";
}

export function visibleAnswers(questions, answers) {
  const out = {};
  for (const q of questions) {
    if (answers[q.id] && isVisible(q, answers)) out[q.id] = answers[q.id];
  }
  return out;
}

export default function Questionnaire({
  questions,
  answers,
  onChange,
  onSubmit,
  submitting,
  error,
}) {
  const sections = [];
  for (const q of questions) {
    if (!isVisible(q, answers)) continue;
    let section = sections.find((s) => s.name === q.section);
    if (!section) {
      section = { name: q.section, items: [] };
      sections.push(section);
    }
    section.items.push(q);
  }

  const answeredCount = Object.keys(visibleAnswers(questions, answers)).length;

  return (
    <div>
      <p className="mb-5 text-sm text-slate-500">
        Technical scans can't see how your business actually operates. Answer
        what you can. "Not sure" counts as a gap, since a control you can't
        confirm can't be counted on.
      </p>

      <div className="space-y-7">
        {sections.map((s) => (
          <div key={s.name}>
            <h3 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500">
              {s.name}
            </h3>
            <div className="space-y-4">
              {s.items.map((q) => (
                <div
                  key={q.id}
                  className={q.depends_on ? "ml-4 border-l-2 border-slate-200 pl-4" : ""}
                >
                  <div className="text-sm font-medium text-slate-900">{q.text}</div>
                  <div className="mt-0.5 text-xs text-slate-500">{q.help}</div>
                  <div className="mt-2 inline-flex overflow-hidden rounded-lg border border-slate-300">
                    {OPTIONS.map((o) => {
                      const active = answers[q.id] === o.value;
                      return (
                        <button
                          key={o.value}
                          type="button"
                          disabled={submitting}
                          onClick={() => onChange(q.id, o.value)}
                          aria-pressed={active}
                          className={`px-4 py-1.5 text-sm ${
                            active
                              ? "bg-slate-900 text-white"
                              : "bg-white text-slate-600 hover:bg-slate-100"
                          }`}
                        >
                          {o.label}
                        </button>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {error && (
        <div className="mt-5 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-800" role="alert">
          {error}
        </div>
      )}

      <button
        type="button"
        onClick={onSubmit}
        disabled={submitting || answeredCount === 0}
        className="mt-6 w-full rounded-lg bg-slate-900 px-4 py-2.5 font-medium text-white hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
      >
        {submitting ? "Updating your score…" : `Update my score (${answeredCount} answered)`}
      </button>
    </div>
  );
}
