/**
 * Notary Forensic Logger SDK — TypeScript implementation
 * Placeholder package. Python SDK currently supports explicit capture,
 * HMAC/Merkle sealing, and local verification; TypeScript parity is not yet
 * implemented here.
 */

export class ForensicSnapshot {
  /**
   * A forensic snapshot of agent execution state.
   */
  constructor(
    public schemaVersion: string,
    public timestamp: string,
    public data: Record<string, unknown>
  ) {}
}

// Placeholder: TypeScript sealing, capture, and verification logic TBD.
