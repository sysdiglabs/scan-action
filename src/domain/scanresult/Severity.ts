export class Severity {
  static readonly Critical = new Severity('Critical', 0);
  static readonly High = new Severity('High', 1);
  static readonly Medium = new Severity('Medium', 2);
  static readonly Low = new Severity('Low', 3);
  static readonly Negligible = new Severity('Negligible', 4);
  static readonly Unknown = new Severity('Unknown', 5);

  private static readonly values: Severity[] = [
    Severity.Critical,
    Severity.High,
    Severity.Medium,
    Severity.Low,
    Severity.Negligible,
    Severity.Unknown,
  ];

  private constructor(public readonly name: string, public readonly value: number) {}

  toString(): string {
    return this.name;
  }

  public static fromString(name: string): Severity {
    return Severity.values.find(s => s.name.toLowerCase() === name.toLowerCase()) || Severity.Unknown;
  }

  public static fromValue(value: number): Severity {
    return Severity.values.find(s => s.value === value) || Severity.Unknown;
  }

  public static getValues(): Severity[] {
    return Severity.values;
  }

  public asNumber(): number {
    return this.value;
  }

  public isEqualTo(other: Severity): boolean {
    return this.value === other.value;
  }

  /**
   * A severity is more severe than another if its value is lower.
   * e.g. Critical (0) is more severe than High (1)
   * @param other Severity to compare to
   * @returns true if this severity is more severe than the other
   */
  public isMoreSevereThan(other: Severity): boolean {
    return this.value < other.value;
  }

  /**
   * A severity is more severe than or equal to another if its value is lower or equal.
   * e.g. Critical (0) is more severe than or equal to High (1)
   * @param other Severity to compare to
   * @returns true if this severity is more severe than or equal to the other
   */
  public isMoreSevereThanOrEqualTo(other: Severity): boolean {
    return this.value <= other.value;
  }

  /**
   * A severity is less severe than another if its value is higher.
   * e.g. Low (3) is less severe than Medium (2)
   * @param other Severity to compare to
   * @returns true if this severity is less severe than the other
   */
  public isLessSevereThan(other: Severity): boolean {
    return this.value > other.value;
  }

  /**
   * A severity is less severe than or equal to another if its value is higher or equal.
   * e.g. Low (3) is less severe than or equal to Medium (2)
   * @param other Severity to compare to
   * @returns true if this severity is less severe than or equal to the other
   */
  public isLessSevereThanOrEqualTo(other: Severity): boolean {
    return this.value >= other.value;
  }
}
