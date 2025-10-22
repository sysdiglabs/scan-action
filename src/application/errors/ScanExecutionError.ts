export class ScanExecutionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScanExecutionError";
  }
}
