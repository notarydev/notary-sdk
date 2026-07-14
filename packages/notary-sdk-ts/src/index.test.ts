import { ForensicSnapshot } from './index';

describe('ForensicSnapshot', () => {
  it('should create a snapshot', () => {
    const snapshot = new ForensicSnapshot('1.0', '2026-07-13T00:00:00Z', {});
    expect(snapshot.schemaVersion).toBe('1.0');
  });
});
