import { EvaluationResult } from './EvaluationResult';
import { PolicyBundle } from './PolicyBundle';

export class PolicyBundleRuleImageConfigFailure {
  constructor(public readonly description: string, public readonly parent: PolicyBundleRule) {}
}

export class PolicyBundleRulePkgVulnFailure {
  constructor(public readonly remediation: string, public readonly parent: PolicyBundleRule) {}
}

export type PolicyBundleRuleFailure =
  | PolicyBundleRuleImageConfigFailure
  | PolicyBundleRulePkgVulnFailure;

export class PolicyBundleRule {
  private readonly failures: PolicyBundleRuleFailure[] = [];

  constructor(
    public readonly id: string,
    public readonly description: string,
    public readonly evaluationResult: EvaluationResult,
    public readonly parent: PolicyBundle
  ) {}

  addImageConfigFailure(remediation: string): PolicyBundleRuleImageConfigFailure {
    const failure = new PolicyBundleRuleImageConfigFailure(remediation, this);
    this.failures.push(failure);
    return failure;
  }

  addPkgVulnFailure(description: string): PolicyBundleRulePkgVulnFailure {
    const failure = new PolicyBundleRulePkgVulnFailure(description, this);
    this.failures.push(failure);
    return failure;
  }

  getFailures(): PolicyBundleRuleFailure[] {
    return this.failures;
  }
}
