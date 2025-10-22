export enum Family {
  Linux,
  Darwin,
  Windows,
  Unknown,
}

export class OperatingSystem {
  constructor(public readonly family: Family, public readonly name: string) {}
}
