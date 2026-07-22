import { ForensicSnapshot, RunCapture, captureRun, instrument, verify } from './index';

describe('ForensicSnapshot', () => {
  it('should create a snapshot', () => {
    const snapshot = new ForensicSnapshot('1.0', '2026-07-13T00:00:00Z', {});
    expect(snapshot.schemaVersion).toBe('1.0');
  });

  it('captures, seals, serializes, and verifies a decision path', () => {
    const capture = new RunCapture('test-secret');
    capture.captureLlm('loan application', 'review policy');
    capture.captureHttp({method: 'POST'}, {score: 681}, 200);
    capture.captureDecision('UNDERWRITING_REVIEW');
    const snapshot = capture.finalize('2026-07-13T00:00:00Z');
    expect(snapshot.toJSON()).toHaveProperty('root_hash', snapshot.rootHash);
    expect((snapshot.toJSON().elements as Array<Record<string, unknown>>)[0]).toHaveProperty('element_hash');
    expect(verify(snapshot, 'test-secret')).toBe(true);
    expect(verify(ForensicSnapshot.fromJson(snapshot.toJson()), 'test-secret')).toBe(true);
    snapshot.elements[0].payload.prompt = 'tampered';
    expect(verify(snapshot, 'test-secret')).toBe(false);
  });

  it('supports a scoped capture helper and result instrumentation', () => {
    const scoped = captureRun('secret', capture => {
      capture.captureDecision('approve');
      return 42;
    });
    expect(scoped.result).toBe(42);
    expect(verify(scoped.snapshot, 'secret')).toBe(true);

    const agent = instrument('secret', (value: string) => value.toUpperCase());
    expect(agent('ok')).toBe('OK');
    expect(agent.notaryLastSnapshot).not.toBeNull();
    expect(verify(agent.notaryLastSnapshot!, 'secret')).toBe(true);
  });

  it('submits the platform-compatible snake_case snapshot contract', async () => {
    const capture = new RunCapture('secret');
    capture.captureDecision('APPROVE');
    const snapshot = capture.finalize();
    const fetchMock = jest.fn().mockResolvedValue({ok: true, status: 200, json: async () => ({id: 'vr-1'})});
    globalThis.fetch = fetchMock as typeof fetch;
    const result = await snapshot.submit('https://api.example.test', 'token', {source_record_ref: 'CASE-1'});
    expect(result.id).toBe('vr-1');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://api.example.test/v1/verification-records/from-snapshot',
      expect.objectContaining({method: 'POST', headers: expect.objectContaining({Authorization: 'Bearer token'})})
    );
    const body = JSON.parse(fetchMock.mock.calls[0][1].body as string);
    expect(body.root_hash).toBe(snapshot.rootHash);
    expect(body.source_record_ref).toBe('CASE-1');
  });
});
