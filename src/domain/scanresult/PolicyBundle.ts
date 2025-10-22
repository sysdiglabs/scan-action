import { EvaluationResult } from './EvaluationResult';
import { Policy } from './Policy';
import { PolicyBundleRule } from './PolicyBundleRule';

export class PolicyBundle {
  private readonly rules: Set<PolicyBundleRule> = new Set();
  private readonly foundInPolicies: WeakSet<Policy> = new WeakSet();

  constructor(public readonly id: string, public readonly name: string) {}

  addPolicy(policy: Policy) {
    if (!this.foundInPolicies.has(policy)) {
      this.foundInPolicies.add(policy);
      policy.addBundle(this);
    }
  }

  addRule(rule: PolicyBundleRule) {
    this.rules.add(rule);
  }

  getRules(): PolicyBundleRule[] {
    return Array.from(this.rules);
  }

  getEvaluationResult(): EvaluationResult {
    for (const rule of this.rules) {
      if (rule.evaluationResult === EvaluationResult.Failed) {
        return EvaluationResult.Failed;
      }
    }
    return EvaluationResult.Passed;
  }
}
