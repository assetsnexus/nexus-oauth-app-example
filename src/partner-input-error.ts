export class PartnerInputError extends Error {
  readonly code = 'VALIDATION';

  constructor(message: string) {
    super(message);
    this.name = 'PartnerInputError';
  }
}
