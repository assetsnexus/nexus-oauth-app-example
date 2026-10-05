import { describe, expect, it } from 'vitest';
import { resolveApprovalUrl } from './approval-url.js';

describe('resolveApprovalUrl', () => {
  const portal = 'https://portal.example';

  it('joins a region path to the portal origin', () => {
    expect(resolveApprovalUrl('/oauth/permission-requests/req-1', portal)).toBe(
      'https://portal.example/oauth/permission-requests/req-1',
    );
  });

  it('keeps an absolute http(s) URL', () => {
    expect(resolveApprovalUrl('https://portal.example/oauth/permission-requests/req-1', portal)).toBe(
      'https://portal.example/oauth/permission-requests/req-1',
    );
    expect(resolveApprovalUrl('http://127.0.0.1:4200/oauth/permission-requests/req-1', portal)).toBe(
      'http://127.0.0.1:4200/oauth/permission-requests/req-1',
    );
  });

  it('rejects non-http schemes and protocol-relative URLs', () => {
    expect(() => resolveApprovalUrl('javascript:alert(1)', portal)).toThrow(/http or https/);
    expect(() => resolveApprovalUrl('data:text/html,hi', portal)).toThrow(/http or https/);
    expect(() => resolveApprovalUrl('//evil.example/oauth/permission-requests/req-1', portal)).toThrow(
      /absolute http/,
    );
  });

  it('rejects a relative path when the portal origin is missing', () => {
    expect(() => resolveApprovalUrl('/oauth/permission-requests/req-1', '')).toThrow(/portal origin/);
  });
});
