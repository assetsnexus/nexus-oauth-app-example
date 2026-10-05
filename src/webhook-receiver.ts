import {
  createIdempotencyStore,
  dispatchWebhookEvent,
  verifySignature,
  type IdempotencyStore,
  type NexusWebhookPayload,
  type WebhookHandlers,
} from '@nexus/webhooks';
import type { PartnerLogger, PartnerState } from './state.js';

export function partnerWebhookHandlers(state: PartnerState, logger: PartnerLogger): WebhookHandlers {
  return {
    'grant.revoked': (payload) => {
      state.revokeGrant(payload.data.grantId);
      logger.info('webhook_grant_revoked', { grantId: payload.data.grantId });
    },
    'grant.fields_changed': (payload) => {
      state.setFields(payload.data.grantId, payload.data.sub, payload.data.grantedFields);
      logger.info('webhook_fields_changed', { grantId: payload.data.grantId, count: payload.data.grantedFields.length });
    },
    'regulatory.status_changed': (payload) => {
      state.setRegulatoryStatus(payload.data.sub, payload.data.status);
      logger.info('webhook_regulatory_status', { status: payload.data.status, bundleSlug: payload.data.bundleSlug });
    },
    'permission_request.decided': (payload) => {
      state.recordDecision(payload.data.requestId);
      logger.info('webhook_permission_decided', { requestId: payload.data.requestId });
    },
    'account.erased': (payload) => {
      const removed = state.eraseSubjects(payload.data.grantIds, payload.data.subs);
      logger.info('webhook_account_erased', { grants: payload.data.grantIds.length, removed });
    },
  };
}

export async function receiveNexusWebhook(opts: {
  rawBody: string;
  headers: Record<string, string | string[] | undefined>;
  secret: string | string[];
  handlers: WebhookHandlers;
  idempotency?: IdempotencyStore;
}): Promise<{ status: number; body: Record<string, unknown> }> {
  if (!verifySignature(opts.rawBody, opts.headers, opts.secret)) {
    return { status: 401, body: { error: 'invalid_signature' } };
  }
  let payload: NexusWebhookPayload;
  try {
    payload = JSON.parse(opts.rawBody) as NexusWebhookPayload;
  } catch {
    return { status: 400, body: { error: 'invalid_json' } };
  }
  if (!payload?.eventId || typeof payload.event !== 'string') {
    return { status: 400, body: { error: 'invalid_payload' } };
  }
  const store = opts.idempotency || createIdempotencyStore();
  if (await store.has(payload.eventId)) {
    return { status: 200, body: { ok: true, duplicate: true } };
  }
  try {
    await dispatchWebhookEvent(payload, opts.handlers);
  } catch {
    // Non-2xx makes Nexus retry the same eventId.
    return { status: 500, body: { error: 'handler_failed' } };
  }
  await store.add(payload.eventId);
  return { status: 200, body: { ok: true } };
}
