import { NexusClient, StaticTokenProvider } from '@nexus/commands-client';
import {
  createMemoryPrivacyJobStore,
  createPrivacyKit,
  createSectionRegistry,
  type PrivacyJobStore,
} from '@nexus/privacy';
import type { PartnerLogger, PartnerState } from './state.js';

export function createPartnerPrivacyKit(opts: {
  issuer: string;
  appToken: string;
  state: PartnerState;
  logger: PartnerLogger;
  store?: PrivacyJobStore;
}) {
  const sections = createSectionRegistry();
  sections.register({
    id: 'grant-mirror',
    export: (ctx) => opts.state.exportSubject(ctx.sub),
    erase: (ctx) => {
      const removed = opts.state.eraseSubjects([ctx.grantId], [ctx.sub]);
      return { deleted: removed, anonymised: 0, retained: [] };
    },
  });
  const client = new NexusClient({
    baseUrl: opts.issuer,
    tokenProvider: new StaticTokenProvider(opts.appToken),
  });
  const kit = createPrivacyKit({
    client,
    store: opts.store ?? createMemoryPrivacyJobStore(),
    sections,
    logger: opts.logger,
    onReview: (job) => {
      opts.logger.info('privacy_review_required', { requestId: job.requestId, type: job.type });
    },
  });
  return kit;
}
