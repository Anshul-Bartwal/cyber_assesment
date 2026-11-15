// Shared styling helpers. Full class names are written out so Tailwind
// can detect them.
export const SEVERITY_BADGE = {
  CRITICAL: "bg-red-100 text-red-800 border-red-200",
  HIGH: "bg-orange-100 text-orange-800 border-orange-200",
  MEDIUM: "bg-yellow-100 text-yellow-800 border-yellow-200",
  LOW: "bg-blue-100 text-blue-800 border-blue-200",
  INFO: "bg-slate-100 text-slate-700 border-slate-200",
};

export const SEVERITY_DOT = {
  CRITICAL: "bg-red-500",
  HIGH: "bg-orange-500",
  MEDIUM: "bg-yellow-500",
  LOW: "bg-blue-500",
  INFO: "bg-slate-400",
};

export function scoreColor(score) {
  if (score >= 80) return { text: "text-green-600", stroke: "stroke-green-500", bar: "bg-green-500" };
  if (score >= 60) return { text: "text-amber-600", stroke: "stroke-amber-500", bar: "bg-amber-500" };
  return { text: "text-red-600", stroke: "stroke-red-500", bar: "bg-red-500" };
}
