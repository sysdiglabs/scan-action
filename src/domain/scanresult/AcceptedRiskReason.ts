export class AcceptedRiskReason {
  static readonly RiskOwned = new AcceptedRiskReason('RiskOwned');
  static readonly RiskTransferred = new AcceptedRiskReason('RiskTransferred');
  static readonly RiskAvoided = new AcceptedRiskReason('RiskAvoided');
  static readonly RiskMitigated = new AcceptedRiskReason('RiskMitigated');
  static readonly RiskNotRelevant = new AcceptedRiskReason('RiskNotRelevant');
  static readonly Custom = new AcceptedRiskReason('Custom');
  static readonly Unknown = new AcceptedRiskReason('Unknown');

  private static readonly values: AcceptedRiskReason[] = [
    AcceptedRiskReason.RiskOwned,
    AcceptedRiskReason.RiskTransferred,
    AcceptedRiskReason.RiskAvoided,
    AcceptedRiskReason.RiskMitigated,
    AcceptedRiskReason.RiskNotRelevant,
    AcceptedRiskReason.Custom,
    AcceptedRiskReason.Unknown,
  ];

  private constructor(public readonly name: string) {}

  public toString(): string {
    return this.name;
  }

  public static fromString(name: string): AcceptedRiskReason {
    const a = AcceptedRiskReason.values.find(p => p.name.toLowerCase() === name.toLowerCase());
    return a || AcceptedRiskReason.Unknown;
  }
}
