export const SeverityNames = ["critical", "high", "medium", "low", "negligible"] as const;
export type Severity = typeof SeverityNames[number];


const severityOrder = ["negligible", "low", "medium", "high", "critical"];

export function isSeverityGte(a: string, b: string): boolean {
  return severityOrder.indexOf(a.toLocaleLowerCase()) >= severityOrder.indexOf(b.toLocaleLowerCase());
}
