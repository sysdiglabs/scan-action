export interface JsonScanResultV1 {
  info: JsonInfo
  scanner: JsonScanner
  result: JsonResult
}

export interface JsonInfo {
  scanTime: string
  scanDuration: string
  resultUrl: string
  resultId: string
}

export interface JsonScanner {
  name: string
  version: string
}

export interface JsonResult {
  assetType: string
  layers: { [key: string]: JsonLayer }
  metadata: JsonMetadata
  packages: { [key: string]: JsonPackage }
  policies: JsonPolicies
  producer: JsonProducer
  riskAccepts?: { [key: string]: any }
  stage: string
  vulnerabilities: { [key: string]: any }
}

export interface JsonLayer {
  command: string
  digest?: string
  index: number
  size?: number | null
}


export interface JsonMetadata {
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

export interface JsonPackage {
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

export interface JsonPolicies {
  evaluations: JsonPolicyEvaluation[]
  globalEvaluation: string
}

export interface JsonPolicyEvaluation {
  name: string
  identifier: string
  description: string
  bundles: JsonBundle[]
  evaluation: string
  createdAt: string
  updatedAt: string
}

export interface JsonBundle {
  name: string
  identifier: string
  type: string
  rules: JsonRule[]
}

export interface JsonRule {
  ruleId: number | string
  ruleType: string
  failureType: string
  description: string
  failures?: JsonRuleFailure[]
  predicates: JsonRulePredicate[]
  evaluationResult: string
}

export interface JsonRuleFailure {
  description?: string
  packageRef: string
  vulnerabilityRef: string
  remediation?: string
  Arguments?: JsonRuleFailureArguments
  riskAcceptRefs?: string[]
}

export interface JsonRuleFailureArguments {
  instructions?: string[]
}


export interface JsonRulePredicate {
  type: string
  extra?: JsonRulePredicateExtra
}

export interface JsonRulePredicateExtra {
  level?: string
  age?: number
  vulnIds?: string[]
}


export interface JsonProducer {
  producedAt: string
}
