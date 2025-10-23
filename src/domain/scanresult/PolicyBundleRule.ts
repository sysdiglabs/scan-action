import { EvaluationResult } from './EvaluationResult';
import { Package } from './Package';
import { PolicyBundle } from './PolicyBundle';
import { Vulnerability } from './Vulnerability';

export interface PolicyBundleRule {
  id: string
  description: string
  evaluationResult: EvaluationResult
  parent: PolicyBundle
}

export function isPkgRule(rule: PolicyBundleRule): rule is PolicyBundleRulePkgVuln {
  return rule instanceof PolicyBundleRulePkgVuln;
}

export function isImageRule(rule: PolicyBundleRule): rule is PolicyBundleRuleImageConfig {
  return rule instanceof PolicyBundleRuleImageConfig;
}

export interface PolicyBundleRuleFailure {
  reason(): string
}

export class PolicyBundleRulePkgVulnFailure implements PolicyBundleRuleFailure {
  constructor(
    public readonly remediation: string,
    public readonly pkg: Package,
    public readonly vuln: Vulnerability,
    public readonly parent: PolicyBundleRulePkgVuln
  ) { }

  reason(): string {
    return `${this.vuln.cve} found in ${this.pkg.name} (${this.pkg.version})`;
  }
}

export class PolicyBundleRulePkgVuln implements PolicyBundleRule {
  private readonly failures: PolicyBundleRulePkgVulnFailure[] = [];
  constructor(
    public readonly id: string,
    public readonly description: string,
    public readonly evaluationResult: EvaluationResult,
    public readonly parent: PolicyBundle
  ) { }

  addFailure(description: string, pkg: Package, vuln: Vulnerability): PolicyBundleRulePkgVulnFailure {
    const failure = new PolicyBundleRulePkgVulnFailure(description, pkg, vuln, this);
    this.failures.push(failure);
    return failure;
  }

  getFailures(): PolicyBundleRulePkgVulnFailure[] {
    return this.failures;
  }
}

export class PolicyBundleRuleImageConfigFailure implements PolicyBundleRuleFailure {
  constructor(public readonly description: string, public readonly parent: PolicyBundleRuleImageConfig) { }

  reason(): string {
    return this.description;
  }
}

export class PolicyBundleRuleImageConfig implements PolicyBundleRule {
  private readonly failures: PolicyBundleRuleImageConfigFailure[] = [];
  constructor(
    public readonly id: string,
    public readonly description: string,
    public readonly evaluationResult: EvaluationResult,
    public readonly parent: PolicyBundle
  ) { }

  addFailure(remediation: string): PolicyBundleRuleImageConfigFailure {
    const failure = new PolicyBundleRuleImageConfigFailure(remediation, this);
    this.failures.push(failure);
    return failure;
  }

  getFailures(): PolicyBundleRuleImageConfigFailure[] {
    return this.failures;
  }
}
