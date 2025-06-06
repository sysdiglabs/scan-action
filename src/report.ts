export interface Report {
  info: Info
  scanner: Scanner
  result: Result
}

export interface Info {
  scanTime: string
  scanDuration: string
  resultUrl: string
  resultId: string
}

export interface Scanner {
  name: string
  version: string
}

export interface Result {
  type: string
  metadata: Metadata
  vulnTotalBySeverity: VulnTotalBySeverity
  fixableVulnTotalBySeverity: FixableVulnTotalBySeverity
  exploitsCount: number
  packages: Package[]
  layers?: Layer[]
  policyEvaluations: PolicyEvaluation[]
  policyEvaluationsResult: string
  riskAcceptanceDefinitions?: RiskAcceptanceDefinition[]
}

export interface Metadata {
  pullString: string
  imageId: string
  digest: string
  baseOs: string
  size: number
  os: string
  architecture: string
  labels?: { [key: string]: string }
  layersCount: number
  createdAt: string
}

export interface VulnTotalBySeverity {
  critical: number
  high: number
  low: number
  medium: number
  negligible: number
}

export interface FixableVulnTotalBySeverity {
  critical: number
  high: number
  low: number
  medium: number
  negligible: number
}

export interface Package {
  type: string
  name: string
  version: string
  path: string
  layerDigest?: string
  suggestedFix?: string
  vulns?: Vuln[]
}

export interface Vuln {
  name: string
  severity: SarifSeverity
  cvssScore: CvssScore
  disclosureDate: string
  solutionDate?: string
  exploitable: boolean
  fixedInVersion?: string
  publishDateByVendor: PublishDateByVendor
  annotations?: { [key: string]: string }
  acceptedRisks?: AcceptedRisk[]
}

export interface FilterOptions {
  minSeverity?: Severity;
  packageTypes?: string[];
  notPackageTypes?: string[];
  excludeAccepted?: boolean;
}


export interface SarifSeverity {
  value: string
  sourceName: string
}

export const SeverityNames = ["critical", "high", "medium", "low", "negligible"] as const;
export type Severity = typeof SeverityNames[number];

export interface CvssScore {
  value: Value
  sourceName: string
}

export interface Value {
  version: string
  score: number
  vector: string
}

export interface PublishDateByVendor {
  nvd?: string
  vulndb: string
  cisakev?: string
}

export interface AcceptedRisk {
  index: number
  ref: string
  id: string
}

export interface Layer {
  digest?: string
  size?: number
  command: string
  vulns: Vulns
  runningVulns: RunningVulns
  baseImages: BaseImage[]
}

export interface Vulns {
  critical?: number
  high?: number
  low?: number
  medium?: number
  negligible?: number
}

export interface RunningVulns { }

export interface BaseImage {
  pullstrings: string[]
}

export interface PolicyEvaluation {
  name: string
  identifier: string
  type: string
  bundles: Bundle[]
  acceptedRiskTotal: number
  evaluationResult: string
  createdAt: string
  updatedAt: string
}

export interface Bundle {
  name: string
  identifier: string
  type: string
  rules: Rule[]
  createdAt: string
  updatedAt: string
}

export interface Rule {
  ruleType: string
  failureType: string
  description: string
  failures?: Failure[]
  evaluationResult: string
  predicates: Predicate[]
}

export interface Failure {
  pkgIndex?: number
  vulnInPkgIndex?: number
  ref?: string
  description?: string
  remediation?: string
  Arguments?: Arguments
  acceptedRisks?: AcceptedRisk[]
}

export interface Arguments {
  instructions?: string[]
}

export interface Predicate {
  type: string
  extra?: Extra
}

export interface Extra {
  level?: string
  age?: number
  vulnIds?: string[]
}

export interface RiskAcceptanceDefinition {
  id: string
  entityType: string
  entityValue: string
  context: any[]
  status: string
  reason: string
  description: string
  expirationDate: string
  createdAt: string
  updatedAt: string
}

const severityOrder = ["negligible", "low", "medium", "high", "critical"];

export function isSeverityGte(a: string, b: string): boolean {
  return severityOrder.indexOf(a.toLocaleLowerCase()) >= severityOrder.indexOf(b.toLocaleLowerCase());
}

export function filterPackages(pkgs: Package[], filters: FilterOptions): Package[] {
  if (!Array.isArray(pkgs)) return [];
  return pkgs
    .filter(pkg => {
      const pkgType = pkg.type?.toLowerCase();
      if (filters.packageTypes && filters.packageTypes.length > 0 &&
        !filters.packageTypes.map(t => t.toLowerCase()).includes(pkgType)) return false;
      if (filters.notPackageTypes && filters.notPackageTypes.length > 0 &&
        filters.notPackageTypes.map(t => t.toLowerCase()).includes(pkgType)) return false;
      return true;
    })
    .map(pkg => {
      let vulns = pkg.vulns?.filter(vuln => {
        if (filters.minSeverity && !isSeverityGte(vuln.severity.value, filters.minSeverity)) return false;
        if (filters.excludeAccepted && Array.isArray(vuln.acceptedRisks) && vuln.acceptedRisks.length > 0) return false;
        return true;
      }) || [];
      return { ...pkg, vulns };
    })
    .filter(pkg => pkg.vulns && pkg.vulns.length > 0);
}
