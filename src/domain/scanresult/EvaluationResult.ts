export class EvaluationResult {
  static readonly Passed = new EvaluationResult('passed');
  static readonly Failed = new EvaluationResult('failed');

  private static readonly values: EvaluationResult[] = [
    EvaluationResult.Passed,
    EvaluationResult.Failed,
  ];

  private constructor(public readonly name: string) {}

  public toString(): string {
    return this.name;
  }

  public isPassed(): boolean {
    return this === EvaluationResult.Passed;
  }

  public isFailed(): boolean {
    return this === EvaluationResult.Failed;
  }

  public static fromString(name: string): EvaluationResult {
    return EvaluationResult.values.find(p => p.name.toLowerCase() === name.toLowerCase()) || EvaluationResult.Failed;
  }
}
