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
  riskAccepts?: { [key: string]: any }
  stage: string
  vulnerabilities: { [key: string]: any }
}

export interface Layer {
  command: string
  digest?: string
  index: number
  size?: number | null
}


export interface Metadata {
  architecture: string
  author: string
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
  vulnerabilitiesRefs: string[] | null
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
  ruleId: number | string
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
