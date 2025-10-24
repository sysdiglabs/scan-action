export class ChecksumVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ChecksumVerificationError';
  }
}
