export class ReportParsingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReportParsingError";
  }
}
