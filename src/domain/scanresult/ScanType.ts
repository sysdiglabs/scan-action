export class ScanType {
  static readonly Docker = new ScanType('Docker');

  private static readonly values: ScanType[] = [
    ScanType.Docker,
  ];

  private constructor(public readonly name: string) {}

  public toString(): string {
    return this.name;
  }
}
