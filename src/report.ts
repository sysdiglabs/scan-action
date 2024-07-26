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
  policyEvaluations: PolicyEvaluation[]
  policyEvaluationsResult: string
}

export interface Metadata {
  pullString: string
  imageId: string
  digest: string
  baseOs: string
  size: number
  os: string
  architecture: string
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
  suggestedFix?: string
  vulns?: Vuln[]
}

export interface Vuln {
  name: string
  severity: Severity
  cvssScore: CvssScore
  disclosureDate: string
  solutionDate?: string
  exploitable: boolean
  fixedInVersion?: string
  publishDateByVendor: PublishDateByVendor
}

export enum Priority {
  critical,
  high,
  medium,
  low,
  negligible,
  any
}

export type SeverityValue = keyof typeof Priority;

export interface Severity {
  value: SeverityValue
  sourceName: string
}

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
  nvd: string
  vulndb: string
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
}

