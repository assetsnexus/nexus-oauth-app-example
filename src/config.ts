import { assertPortalOrigin } from './approval-url.js';

export type PartnerConfig = {
  issuer: string;
  portalOrigin: string;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  webhookSecret: string;
  port: number;
};

export function loadConfig(env: NodeJS.ProcessEnv = process.env): PartnerConfig {
  const issuer = (env.NEXUS_ISSUER || '').replace(/\/+$/, '');
  const portalOrigin = (env.NEXUS_PORTAL_ORIGIN || '').replace(/\/+$/, '');
  const clientId = env.NEXUS_CLIENT_ID || '';
  const redirectUri = env.NEXUS_REDIRECT_URI || '';
  const webhookSecret = env.NEXUS_WEBHOOK_SECRET || '';
  const port = Number(env.PORT || 8787);
  return {
    issuer,
    portalOrigin,
    clientId,
    clientSecret: env.NEXUS_CLIENT_SECRET || undefined,
    redirectUri,
    webhookSecret,
    port: Number.isFinite(port) ? port : 8787,
  };
}

export function assertConfig(config: PartnerConfig): void {
  const missing = [
    ['NEXUS_ISSUER', config.issuer],
    ['NEXUS_PORTAL_ORIGIN', config.portalOrigin],
    ['NEXUS_CLIENT_ID', config.clientId],
    ['NEXUS_REDIRECT_URI', config.redirectUri],
    ['NEXUS_WEBHOOK_SECRET', config.webhookSecret],
  ].filter(([, value]) => !value);
  if (missing.length) {
    throw new Error(`Missing partner env: ${missing.map(([name]) => name).join(', ')}`);
  }
  try {
    assertPortalOrigin(config.portalOrigin);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'invalid portal origin';
    throw new Error(`NEXUS_PORTAL_ORIGIN: ${message}`);
  }
}
