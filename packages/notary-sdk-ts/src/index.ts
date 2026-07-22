/**
 * Notary Forensic Logger SDK for TypeScript.
 *
 * Capture is explicit by design: callers choose which model, tool, and
 * decision boundaries become part of the sealed verification record.
 */

import { createHash, createHmac, timingSafeEqual } from "crypto";

export const SCHEMA_VERSION = 1;

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

export type CaptureKind = "llm" | "http" | "decision" | "rng_seed" | "timestamp" | string;

export interface CapturedElementData {
  kind: CaptureKind;
  payload: Record<string, unknown>;
  elementHash?: string;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, item]) => [key, canonicalize(item)])
    );
  }
  return value;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function secretBytes(secret: string | Uint8Array): Uint8Array {
  return typeof secret === "string" ? new TextEncoder().encode(secret) : secret;
}

function hex(buffer: Uint8Array): string {
  return Array.from(buffer, byte => byte.toString(16).padStart(2, "0")).join("");
}

function bytes(value: string): Buffer {
  return Buffer.from(value, "hex");
}

export class CapturedElement implements CapturedElementData {
  public elementHash: string;

  constructor(
    public kind: CaptureKind,
    public payload: Record<string, unknown> = {},
    elementHash = ""
  ) {
    this.elementHash = elementHash;
  }

  canonicalBytes(): Uint8Array {
    return new TextEncoder().encode(canonicalJson({ kind: this.kind, payload: this.payload }));
  }

  toJSON(): CapturedElementData {
    return { kind: this.kind, payload: this.payload, element_hash: this.elementHash } as CapturedElementData;
  }

  static fromJSON(value: CapturedElementData): CapturedElement {
    const raw = value as CapturedElementData & { element_hash?: string };
    return new CapturedElement(value.kind, { ...value.payload }, raw.element_hash || value.elementHash || "");
  }
}

export class ForensicSnapshot {
  public elements: CapturedElement[];
  public merkleChain: string[];
  public rootHash: string;

  constructor(
    public schemaVersion: string | number,
    public timestamp: string,
    data: Record<string, unknown> = {}
  ) {
    const rawElements = Array.isArray(data.elements) ? data.elements : [];
    this.elements = rawElements.map(value => CapturedElement.fromJSON(value as CapturedElementData));
    this.merkleChain = Array.isArray(data.merkleChain) ? data.merkleChain.map(String) : [];
    this.rootHash = typeof data.rootHash === "string" ? data.rootHash : "";
  }

  toJSON(): Record<string, unknown> {
    return {
      schema_version: this.schemaVersion,
      timestamp: this.timestamp,
      elements: this.elements.map(element => element.toJSON()),
      merkle_chain: this.merkleChain,
      root_hash: this.rootHash,
    };
  }

  toJson(): string {
    return canonicalJson(this.toJSON());
  }

  static fromJSON(value: Record<string, unknown>): ForensicSnapshot {
    return new ForensicSnapshot(
      (value.schema_version as string | number) ?? (value.schemaVersion as string | number) ?? 0,
      String(value.timestamp || ""),
      {
        ...value,
        elements: value.elements,
        merkleChain: value.merkle_chain ?? value.merkleChain,
        rootHash: value.root_hash ?? value.rootHash,
      }
    );
  }

  static fromJson(raw: string): ForensicSnapshot {
    return ForensicSnapshot.fromJSON(JSON.parse(raw) as Record<string, unknown>);
  }

  async submit(
    apiUrl: string,
    apiToken = "",
    metadata: Record<string, unknown> = {}
  ): Promise<Record<string, unknown>> {
    const baseUrl = apiUrl.replace(/\/$/, "");
    if (!baseUrl) throw new Error("apiUrl must be non-empty");
    const response = await globalThis.fetch(`${baseUrl}/v1/verification-records/from-snapshot`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(apiToken ? {Authorization: `Bearer ${apiToken}`} : {}),
      },
      body: JSON.stringify({...this.toJSON(), ...metadata}),
    });
    if (!response.ok) throw new Error(`Platform submission failed: ${response.status}`);
    const result: unknown = await response.json();
    if (!result || typeof result !== "object" || Array.isArray(result)) {
      throw new Error("platform response must be a JSON object");
    }
    return result as Record<string, unknown>;
  }
}

export function sealElement(prevHash: Uint8Array, data: Uint8Array, secret: string | Uint8Array): Uint8Array {
  if (!secretBytes(secret).length) throw new Error("secret must be non-empty");
  const hmac = createHmac("sha256", secretBytes(secret));
  hmac.update(Buffer.from(prevHash));
  hmac.update(Buffer.from(data));
  return hmac.digest();
}

export function computeRootHash(elementHashes: Uint8Array[]): string {
  if (!elementHashes.length) throw new Error("elementHashes must not be empty");
  let current: Uint8Array[] = elementHashes.map(hash => new Uint8Array(hash));
  if (current.some(hash => hash.length !== 32)) throw new Error("every element hash must be 32 bytes");
  while (current.length > 1) {
    const next: Uint8Array[] = [];
    for (let index = 0; index < current.length; index += 2) {
      const right = current[index + 1] || current[index];
      next.push(createHash("sha256").update(Buffer.concat([current[index], right])).digest());
    }
    current = next;
  }
  return Buffer.from(current[0]).toString("hex");
}

export class RunCapture {
  private readonly secret: Uint8Array;
  private readonly captured: CapturedElement[] = [];
  private sealedSnapshot: ForensicSnapshot | null = null;

  constructor(secret: string | Uint8Array) {
    this.secret = secretBytes(secret);
    if (!this.secret.length) throw new Error("secret must be non-empty");
  }

  get snapshot(): ForensicSnapshot | null {
    return this.sealedSnapshot;
  }

  captureLlm(prompt?: unknown, response?: unknown, metadata?: Record<string, unknown>): void {
    const payload: Record<string, unknown> = {};
    if (prompt !== undefined) payload.prompt = prompt;
    if (response !== undefined) payload.response = response;
    if (metadata) payload.metadata = metadata;
    this.captured.push(new CapturedElement("llm", payload));
  }

  captureHttp(request?: unknown, response?: unknown, status?: number): void {
    const payload: Record<string, unknown> = {};
    if (request !== undefined) payload.request = request;
    if (response !== undefined) payload.response = response;
    if (status !== undefined) payload.status = status;
    this.captured.push(new CapturedElement("http", payload));
  }

  captureDecision(decision?: unknown): void {
    this.captured.push(new CapturedElement("decision", { decision }));
  }

  captureRngSeed(seed?: unknown): void {
    this.captured.push(new CapturedElement("rng_seed", { seed }));
  }

  captureTimestamp(timestamp = ""): void {
    this.captured.push(new CapturedElement("timestamp", { timestamp }));
  }

  finalize(timestamp = new Date().toISOString()): ForensicSnapshot {
    if (!this.captured.length) throw new Error("no elements captured");
    let previous = Buffer.alloc(32);
    const chain: string[] = [];
    for (const element of this.captured) {
      const digest = sealElement(previous, element.canonicalBytes(), this.secret);
      element.elementHash = hex(digest);
      chain.push(element.elementHash);
      previous = Buffer.from(digest);
    }
    const snapshot = new ForensicSnapshot(SCHEMA_VERSION, timestamp, {
      elements: this.captured,
      merkleChain: chain,
      rootHash: computeRootHash(chain.map(bytes)),
    });
    this.sealedSnapshot = snapshot;
    return snapshot;
  }
}

export function verify(snapshot: ForensicSnapshot, secret: string | Uint8Array): boolean {
  try {
    if (!snapshot.elements.length || !secretBytes(secret).length) return false;
    let previous = Buffer.alloc(32);
    const hashes: Buffer[] = [];
    for (const element of snapshot.elements) {
      const digest = Buffer.from(sealElement(previous, element.canonicalBytes(), secret));
      const stored = bytes(element.elementHash);
      if (stored.length !== digest.length || !timingSafeEqual(stored, digest)) return false;
      hashes.push(digest);
      previous = digest;
    }
    return Boolean(snapshot.rootHash) && computeRootHash(hashes) === snapshot.rootHash;
  } catch {
    return false;
  }
}

export function captureRun<T>(secret: string | Uint8Array, fn: (capture: RunCapture) => T): { result: T; snapshot: ForensicSnapshot } {
  const capture = new RunCapture(secret);
  const result = fn(capture);
  return { result, snapshot: capture.finalize() };
}

export function instrument<TArgs extends unknown[], TResult>(
  secret: string | Uint8Array,
  fn: (...args: TArgs) => TResult
): ((...args: TArgs) => TResult) & { notaryLastSnapshot: ForensicSnapshot | null } {
  const wrapped = ((...args: TArgs): TResult => {
    const capture = new RunCapture(secret);
    try {
      const result = fn(...args);
      capture.captureDecision({ result });
      wrapped.notaryLastSnapshot = capture.finalize();
      return result;
    } catch (error) {
      capture.captureDecision({ error: true });
      wrapped.notaryLastSnapshot = capture.finalize();
      throw error;
    }
  }) as ((...args: TArgs) => TResult) & { notaryLastSnapshot: ForensicSnapshot | null };
  wrapped.notaryLastSnapshot = null;
  return wrapped;
}
