import { randomUUID } from 'node:crypto';
import {
  ElevationRequiredError,
  FieldClaimValidationError,
  NexusClient,
  NexusError,
  PermissionBatchValidationError,
  StaticTokenProvider,
  buildAuthorizeUrl,
  exchangeAuthorizationCode,
  generateOAuthState,
  generatePkce,
  verifyAttestation,
  type JwksKeySource,
  type PermissionBatchItem,
} from '@nexus/commands-client';
import { assertPortalOrigin, resolveApprovalUrl } from './approval-url.js';
import { PartnerInputError } from './partner-input-error.js';
import type { PartnerLogger, PartnerSession, PartnerState } from './state.js';

export { PartnerInputError } from './partner-input-error.js';

type Exchange = typeof exchangeAuthorizationCode;

export type PartnerServiceOptions = {
  issuer: string;
  /** Portal origin used to open region approval paths. http: or https: only. */
  portalOrigin: string;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  jwks: JwksKeySource;
  state: PartnerState;
  logger?: PartnerLogger;
  clientForToken?: (accessToken: string) => NexusClient;
  exchange?: Exchange;
};

export type PartnerHttpError = {
  status: number;
  body: Record<string, unknown>;
};

const silent: PartnerLogger = { info() {}, warn() {} };

export class PartnerService {
  private readonly logger: PartnerLogger;

  constructor(private readonly opts: PartnerServiceOptions) {
    assertPortalOrigin(opts.portalOrigin);
    this.logger = opts.logger || silent;
  }

  async startLogin(input: {
    subjectType: 'user' | 'org_member';
    orgId?: string;
  }): Promise<{ sessionId: string; authorizeUrl: string }> {
    if (input.subjectType !== 'user' && input.subjectType !== 'org_member') {
      throw new PartnerInputError('subjectType must be user or org_member');
    }
    if (input.subjectType === 'org_member' && !input.orgId?.trim()) {
      throw new PartnerInputError('orgId is required for an org-member login');
    }
    const pkce = await generatePkce();
    const state = generateOAuthState();
    const session: PartnerSession = { id: randomUUID() };
    session.intent = {
      state,
      codeVerifier: pkce.codeVerifier,
      subjectType: input.subjectType,
      ...(input.orgId ? { orgId: input.orgId.trim() } : {}),
    };
    this.opts.state.saveSession(session);
    const authorizeUrl = buildAuthorizeUrl({
      issuer: this.opts.issuer,
      clientId: this.opts.clientId,
      redirectUri: this.opts.redirectUri,
      state,
      codeChallenge: pkce.codeChallenge,
      subjectType: input.subjectType,
      ...(input.orgId ? { orgId: input.orgId.trim() } : {}),
      scope: 'openid',
    });
    this.logger.info('authorize_started', { subjectType: input.subjectType, orgId: input.orgId || null });
    return { sessionId: session.id, authorizeUrl };
  }

  async completeLogin(input: { sessionId: string; code: string; state: string }): Promise<void> {
    const session = this.requireSession(input.sessionId);
    if (!session.intent || session.intent.state !== input.state) {
      this.logger.warn('authorize_state_mismatch', { sessionId: session.id });
      throw new NexusError('INVALID_GRANT', 'OAuth state does not match this session');
    }
    const exchange = this.opts.exchange || exchangeAuthorizationCode;
    const token = await exchange({
      issuer: this.opts.issuer,
      clientId: this.opts.clientId,
      clientSecret: this.opts.clientSecret,
      code: input.code,
      redirectUri: this.opts.redirectUri,
      codeVerifier: session.intent.codeVerifier,
    });
    session.accessToken = token.access_token;
    session.refreshToken = token.refresh_token;
    session.subjectType = token.subject_type || session.intent.subjectType;
    session.orgId = token.org_id || session.intent.orgId;
    session.intent = undefined;
    this.opts.state.saveSession(session);
    this.logger.info('authorize_completed', { subjectType: session.subjectType || null });
  }

  async identities(sessionId: string) {
    const client = this.client(sessionId);
    return client.subject.identities();
  }

  async status(sessionId: string) {
    const client = this.client(sessionId);
    const raw = await client.subject.regulatoryStatus();
    try {
      const claims = await verifyAttestation({
        attestation: raw.attestation,
        issuer: this.opts.issuer,
        audience: this.opts.clientId,
        jwks: this.opts.jwks,
        logger: { warn: (message, meta) => this.logger.warn(message, meta) },
      });
      this.logger.info('regulatory_status_verified', { rows: claims.statuses.length });
      return {
        statuses: claims.statuses,
        attestationExpiresAt: raw.attestationExpiresAt,
        subjectType: claims.subjectType,
      };
    } catch (err) {
      this.logger.warn('regulatory_status_rejected', {
        code: err instanceof NexusError ? err.code : 'ATTESTATION_INVALID',
      });
      throw err;
    }
  }

  async fields(sessionId: string) {
    return this.client(sessionId).subject.fields.get();
  }

  async requestFields(sessionId: string, fields: Array<{ field: string; purpose?: string }>) {
    this.logger.info('fields_request', { count: fields.length });
    return this.client(sessionId).subject.fields.request(fields);
  }

  /** `anx.oauth2.app-subscription.get`. The region currently returns only the free tier. */
  async subscription(sessionId: string) {
    return this.client(sessionId).subscriptions.getActiveTier();
  }

  /**
   * Org security policy and compliance overview.
   * Pass a client authenticated as the org member or with an org API key.
   * An app access token is forbidden for these commands.
   */
  async orgCompliance(admin: NexusClient) {
    const [policy, overview] = await Promise.all([
      admin.orgAdmin.securityPolicy(),
      admin.orgAdmin.complianceOverview(),
    ]);
    return { policy, overview };
  }

  async requestBatch(sessionId: string, items: PermissionBatchItem[]) {
    const batch = await this.client(sessionId).permissions.requestBatch({ items });
    let approvalUrl: string;
    try {
      approvalUrl = resolveApprovalUrl(batch.approvalUrl, this.opts.portalOrigin);
    } catch (err) {
      this.logger.warn('approval_url_rejected', {
        requestId: batch.requestId,
        message: err instanceof Error ? err.message : 'invalid approval URL',
      });
      throw err;
    }
    this.logger.info('permission_batch', { requestId: batch.requestId, created: batch.created });
    return { requestId: batch.requestId, approvalUrl, status: batch.status };
  }

  private client(sessionId: string): NexusClient {
    const session = this.requireSession(sessionId);
    if (!session.accessToken) {
      throw new NexusError('UNAUTHORIZED', 'Login with Nexus is required');
    }
    if (this.opts.clientForToken) return this.opts.clientForToken(session.accessToken);
    return new NexusClient({
      baseUrl: this.opts.issuer,
      tokenProvider: new StaticTokenProvider(session.accessToken),
    });
  }

  private requireSession(sessionId: string): PartnerSession {
    const session = this.opts.state.session(sessionId);
    if (!session) throw new NexusError('UNAUTHORIZED', 'Session not found');
    return session;
  }
}

export function mapPartnerError(err: unknown, portalOrigin = ''): PartnerHttpError {
  if (err instanceof ElevationRequiredError) {
    try {
      return {
        status: 409,
        body: {
          error: 'PERMISSION_ELEVATION_REQUIRED',
          approvalUrl: resolveApprovalUrl(err.approvalUrl, portalOrigin),
          elevationRequestId: err.elevationRequestId,
        },
      };
    } catch (resolveErr) {
      if (resolveErr instanceof PartnerInputError) {
        return { status: 400, body: { error: resolveErr.code, message: resolveErr.message } };
      }
      throw resolveErr;
    }
  }
  if (err instanceof FieldClaimValidationError || err instanceof PermissionBatchValidationError || err instanceof PartnerInputError) {
    return { status: 400, body: { error: err.code, message: err.message } };
  }
  if (err instanceof NexusError) {
    const body: Record<string, unknown> = { error: err.code, message: err.message };
    if (Array.isArray(err.meta?.missing)) body.missing = err.meta.missing;
    if (Array.isArray(err.meta?.actions)) body.actions = err.meta.actions;
    return { status: err.httpStatus || 500, body };
  }
  return { status: 500, body: { error: 'INTERNAL' } };
}
