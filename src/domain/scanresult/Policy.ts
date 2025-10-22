import { EvaluationResult } from './EvaluationResult';
import { PolicyBundle } from './PolicyBundle';

export class Policy {
  private readonly bundles: WeakSet<PolicyBundle> = new WeakSet();

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

  getEvaluationResult(): EvaluationResult {
    // As WeakSet is not iterable, we can't implement this here.
    // This logic will be handled in the ScanResult class.
    throw new Error('WeakSet is not iterable. Cannot get evaluation result from policy.');
  }
}
