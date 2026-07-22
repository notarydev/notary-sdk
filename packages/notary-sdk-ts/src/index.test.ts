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
});
