export class Family {
  static readonly Linux = new Family('Linux');
  static readonly Darwin = new Family('Darwin');
  static readonly Windows = new Family('Windows');
  static readonly Unknown = new Family('Unknown');

  private static readonly values: Family[] = [
    Family.Linux,
    Family.Darwin,
    Family.Windows,
    Family.Unknown,
  ];

  private constructor(public readonly name: string) {}

  public toString(): string {
    return this.name;
  }

  public static fromString(name: string): Family {
    return Family.values.find(p => p.name.toLowerCase() === name.toLowerCase()) || Family.Unknown;
  }
}

export class OperatingSystem {
  constructor(public readonly family: Family, public readonly name: string) {}
}
