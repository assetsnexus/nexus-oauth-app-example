export type LoginIntent = {
  state: string;
  codeVerifier: string;
  subjectType: 'user' | 'org_member';
  orgId?: string;
};

export type PartnerSession = {
  id: string;
  accessToken?: string;
  refreshToken?: string;
  subjectType?: string;
  orgId?: string;
  intent?: LoginIntent;
};

export type GrantMirror = {
  grantId: string;
  sub: string;
  revoked: boolean;
  grantedFields: string[];
  regulatoryStatus: string | null;
  lastDecisionId?: string;
};

const REDACTED = new Set([
  'accessToken',
  'refreshToken',
  'attestation',
  'code',
  'codeVerifier',
  'clientSecret',
  'authorization',
]);

export type PartnerLogger = {
  info: (message: string, meta?: Record<string, unknown>) => void;
  warn: (message: string, meta?: Record<string, unknown>) => void;
};

export function createPartnerLogger(): PartnerLogger {
  const write = (level: 'info' | 'warn', message: string, meta?: Record<string, unknown>) => {
    const safe: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(meta || {})) {
      if (REDACTED.has(key)) continue;
      safe[key] = value;
    }
    const line = JSON.stringify({ level, message, ...safe });
    if (level === 'warn') console.warn(line);
    else console.info(line);
  };
  return {
    info: (message, meta) => write('info', message, meta),
    warn: (message, meta) => write('warn', message, meta),
  };
}

export class PartnerState {
  readonly sessions = new Map<string, PartnerSession>();
  readonly grants = new Map<string, GrantMirror>();

  session(id: string): PartnerSession | undefined {
    return this.sessions.get(id);
  }

  saveSession(session: PartnerSession): void {
    this.sessions.set(session.id, session);
  }

  revokeGrant(grantId: string): void {
    const row = this.grants.get(grantId);
    if (row) row.revoked = true;
    else this.grants.set(grantId, emptyGrant(grantId, '', true));
  }

  setFields(grantId: string, sub: string, grantedFields: string[]): void {
    const row = this.ensure(grantId, sub);
    row.grantedFields = [...grantedFields];
  }

  setRegulatoryStatus(sub: string, status: string): void {
    for (const row of this.grants.values()) {
      if (row.sub === sub) row.regulatoryStatus = status;
    }
  }

  exportSubject(sub: string): Array<Pick<GrantMirror, 'grantId' | 'sub' | 'grantedFields' | 'regulatoryStatus' | 'revoked'>> {
    return [...this.grants.values()]
      .filter((row) => row.sub === sub)
      .map((row) => ({
        grantId: row.grantId,
        sub: row.sub,
        grantedFields: row.grantedFields,
        regulatoryStatus: row.regulatoryStatus,
        revoked: row.revoked,
      }));
  }

  /** Drops every mirrored grant listed or held by one of the erased pairwise subjects. */
  eraseSubjects(grantIds: string[], subs: string[]): number {
    const ids = new Set(grantIds);
    const subjects = new Set(subs);
    let removed = 0;
    for (const [grantId, row] of this.grants) {
      if (ids.has(grantId) || subjects.has(row.sub)) {
        this.grants.delete(grantId);
        removed += 1;
      }
    }
    return removed;
  }

  recordDecision(requestId: string): void {
    for (const row of this.grants.values()) row.lastDecisionId = requestId;
  }

  private ensure(grantId: string, sub: string): GrantMirror {
    const existing = this.grants.get(grantId);
    if (existing) {
      if (sub) existing.sub = sub;
      return existing;
    }
    const created = emptyGrant(grantId, sub, false);
    this.grants.set(grantId, created);
    return created;
  }
}

function emptyGrant(grantId: string, sub: string, revoked: boolean): GrantMirror {
  return {
    grantId,
    sub,
    revoked,
    grantedFields: [],
    regulatoryStatus: null,
  };
}
