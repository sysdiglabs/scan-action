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
  assetType: string
  layers: { [key: string]: Layer }
  metadata: Metadata
  packages: { [key: string]: Package }
  policies: Policies
  producer: Producer
  riskAccepts?: { [key: string]: RiskAcceptanceDefinition }
  stage: string
  vulnerabilities: { [key: string]: Vulnerability }
}

export interface Layer {
  command: string
  digest?: string
  index: number
  size?: number
}


export interface Metadata {
  architecture: string
  autor: string
  baseOs: string
  createdAt: string
  digest: string
  imageId: string
  labels?: { [key: string]: string }
  os: string
  pullString: string
  size: number
}

export interface Package {
  isRemoved: boolean
  isRunning: boolean
  layerRef: string
  name: string
  path: string
  suggestedFix?: string
  type: string
  version: string
  vulnerabilitiesRefs: string[]
}

export interface Policies {
  evaluations: PolicyEvaluation[]
  globalEvaluation: string
}

export interface PolicyEvaluation {
  name: string
  identifier: string
  description: string
  bundles: Bundle[]
  evaluation: string
  createdAt: string
  updatedAt: string
}

export interface Bundle {
  name: string
  identifier: string
  type: string
  rules: Rule[]
}

export interface Rule {
  ruleId: number
  ruleType: string
  failureType: string
  description: string
  failures?: Failure[]
  predicates: Predicate[]
  evaluationResult: string
}

export interface Failure {
  description?: string
  packageRef: string
  vulnerabilityRef: string
  remediation?: string
  Arguments?: Arguments
  riskAcceptRefs?: string[]
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


export interface Producer {
  producedAt: string
}

export interface Vulnerability {
  cvssScore: CvssScore
  disclosureDate: string
  exploitable: boolean
  fixVersion?: string
  mainProvider: string
  name: string
  packageRef: string
  providersMetadata: { [key: string]: ProviderMetadata }
  riskAcceptRefs?: string[]
  severity: string
  solutionDate?: string
}

export interface CvssScore {
  version: string
  score: number
  vector: string
}

export interface ProviderMetadata {
  severity?: string
  cvssScore?: CvssScore
  publicationDate?: string
  epssScore?: object
}

export interface RiskAcceptanceDefinition {
  context: any[]
  createdAt: string
  description: string
  entityType: string
  entityValue: string
  expirationDate: string
  id: string
  reason: string
  status: string
  updatedAt: string
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


const severityOrder = ["negligible", "low", "medium", "high", "critical"];

export function isSeverityGte(a: string, b: string): boolean {
  return severityOrder.indexOf(a.toLocaleLowerCase()) >= severityOrder.indexOf(b.toLocaleLowerCase());
}

export function filterPackages(pkgs: {[key:string]: Package}, vulns: {[key:string]: Vulnerability}, filters: FilterOptions): {[key:string]: Package} {
  const filteredPackages = Object.entries(pkgs)
    .filter(([key, pkg]) => {
      const pkgType = pkg.type?.toLowerCase();
      if (filters.packageTypes && filters.packageTypes.length > 0 &&
        !filters.packageTypes.map(t => t.toLowerCase()).includes(pkgType)) return false;
      if (filters.notPackageTypes && filters.notPackageTypes.length > 0 &&
        filters.notPackageTypes.map(t => t.toLowerCase()).includes(pkgType)) return false;
      return true;
    })

    return Object.fromEntries(filteredPackages
      .map(([key, pkg]) => {
        let vulnRefs = pkg.vulnerabilitiesRefs?.filter((vulnRef: string) => {
          const vuln = vulns[vulnRef];
          if (filters.minSeverity && vuln && !isSeverityGte(vuln.severity, filters.minSeverity)) {
            return false;
          }
          if (filters.excludeAccepted && vuln && Array.isArray(vuln.riskAcceptRefs) && vuln.riskAcceptRefs.length > 0) return false;
          return true;
        });
        const filteredPackage = { ...pkg, vulnerabilitiesRefs: vulnRefs}
        return [ key, filteredPackage] as [string, Package];
      })
      .filter(([key, pkg]) => pkg.vulnerabilitiesRefs && pkg.vulnerabilitiesRefs.length > 0));
}
