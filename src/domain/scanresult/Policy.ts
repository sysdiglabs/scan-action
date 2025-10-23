import { EvaluationResult } from './EvaluationResult';
import { PolicyBundle } from './PolicyBundle';

export class Policy {
  private readonly bundles: Set<PolicyBundle> = new Set();

  constructor(
    public readonly id: string,
    public readonly name: string,
    public readonly createdAt: Date,
    public readonly updatedAt: Date
  ) {}

  addBundle(bundle: PolicyBundle) {
    if (!this.bundles.has(bundle)) {
      this.bundles.add(bundle);
      bundle.addPolicy(this);
    }
  }

  getBundles(): PolicyBundle[] {
    return Array.from(this.bundles);
  }

  getEvaluationResult(): EvaluationResult {
    for (const bundle of this.bundles) {
      if (bundle.getEvaluationResult().isFailed()) {
        return EvaluationResult.Failed;
      }
    }
    return EvaluationResult.Passed;
  }
}
