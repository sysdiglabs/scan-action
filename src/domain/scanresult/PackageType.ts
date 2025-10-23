export class PackageType {
  static readonly Unknown = new PackageType('Unknown');
  static readonly Os = new PackageType('Os');
  static readonly Python = new PackageType('Python');
  static readonly Java = new PackageType('Java');
  static readonly Javascript = new PackageType('Javascript');
  static readonly Golang = new PackageType('Golang');
  static readonly Rust = new PackageType('Rust');
  static readonly Ruby = new PackageType('Ruby');
  static readonly Php = new PackageType('Php');
  static readonly CSharp = new PackageType('CSharp');

  private static readonly values: PackageType[] = [
    PackageType.Unknown,
    PackageType.Os,
    PackageType.Python,
    PackageType.Java,
    PackageType.Javascript,
    PackageType.Golang,
    PackageType.Rust,
    PackageType.Ruby,
    PackageType.Php,
    PackageType.CSharp,
  ];

  private constructor(public readonly name: string) {}

  public toString(): string {
    return this.name;
  }

  public static fromString(name: string): PackageType {
    if (name.toLowerCase() === 'c#') {
      return PackageType.CSharp;
    }
    return PackageType.values.find(p => p.name.toLowerCase() === name.toLowerCase()) || PackageType.Unknown;
  }
}
