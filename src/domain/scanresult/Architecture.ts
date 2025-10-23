export class Architecture {
  static readonly Amd64 = new Architecture('Amd64');
  static readonly Arm64 = new Architecture('Arm64');
  static readonly Unknown = new Architecture('Unknown');

  private static readonly values: Architecture[] = [
    Architecture.Amd64,
    Architecture.Arm64,
    Architecture.Unknown,
  ];

  private constructor(public readonly name: string) {}

  public toString(): string {
    return this.name;
  }

  public static fromString(name: string): Architecture {
    return Architecture.values.find(p => p.name.toLowerCase() === name.toLowerCase()) || Architecture.Unknown;
  }
}
