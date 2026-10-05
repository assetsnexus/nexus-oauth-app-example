import { PartnerInputError } from './partner-input-error.js';

/**
 * Region approval links are portal paths (`/oauth/permission-requests/<id>`).
 * The browser must not resolve them against the partner origin.
 * Absolute URLs are accepted only for http: and https:.
 */
export function resolveApprovalUrl(raw: string | null | undefined, portalOrigin: string): string {
  const value = typeof raw === 'string' ? raw.trim() : '';
  if (!value) return '';

  let url: URL;
  if (value.startsWith('/') && !value.startsWith('//') && !value.startsWith('/\\')) {
    url = new URL(value, parseHttpOrigin(portalOrigin));
  } else {
    try {
      url = new URL(value);
    } catch {
      throw new PartnerInputError('approval URL must be an absolute http(s) URL or a portal path');
    }
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new PartnerInputError('approval URL must use http or https');
  }
  if (!url.hostname) {
    throw new PartnerInputError('approval URL must include a host');
  }
  return url.toString();
}

export function assertPortalOrigin(raw: string): string {
  return parseHttpOrigin(raw);
}

function parseHttpOrigin(raw: string): string {
  const trimmed = typeof raw === 'string' ? raw.trim() : '';
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new PartnerInputError('portal origin must be an http(s) URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new PartnerInputError('portal origin must use http or https');
  }
  if (!url.hostname) {
    throw new PartnerInputError('portal origin must include a host');
  }
  return url.origin;
}
