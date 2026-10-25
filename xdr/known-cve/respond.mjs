import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_LOG_PATH = join(dirname(dirname(fileURLToPath(import.meta.url))), 'alerts.log');
const DEFAULT_TTL_MS = 10 * 60 * 1000;
const ALERT_ID = /^[a-zA-Z0-9._-]{1,80}$/u;
const ACTIONS = new Set(['block', 'alert', 'record']);
const REASONS = Object.freeze({
  HEADER_JNDI: '머리글의 명시적 JNDI 원격 조회 구문',
  URL_JNDI: 'URL 또는 요청 인자의 명시적 JNDI 원격 조회 구문',
  SCANNER_TRACE: '명시적 Log4Shell 취약점 점검 도구 흔적',
});

function checkedAddress(value) {
  if (typeof value !== 'string') return null;
  const address = value.trim();
  return isIP(address) ? address : null;
}

function hasT1190(mitre) {
  return Array.isArray(mitre) && mitre.some((item) => item === 'T1190');
}

function hasJndiRemoteLookup(value) {
  return /\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|corba|nis)\s*:/iu.test(
    typeof value === 'string' ? value : '',
  );
}

function isExplicitScannerTrace(description) {
  const value = typeof description === 'string' ? description : '';
  return /알려진\s*취약점\s*점검\s*흔적|(?:log4shell|cve[- ]?2021[- ]?44228).{0,40}(?:점검|scanner|scan)/iu.test(value);
}

function safeDecision(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
    && ACTIONS.has(value.action)
    && Number.isFinite(value.confidence) && value.confidence >= 0 && value.confidence <= 1
    && typeof value.reason === 'string' && value.reason.trim().length > 0;
}

function verifiedReason(alert, reason) {
  if (!hasT1190(alert?.rule?.mitre)) return null;
  const headerLookup = hasJndiRemoteLookup(alert?.data?.useragent);
  const urlLookup = hasJndiRemoteLookup(alert?.data?.url);
  if (reason === REASONS.HEADER_JNDI && headerLookup) return reason;
  if (reason === REASONS.URL_JNDI && urlLookup) return reason;
  if (reason === REASONS.SCANNER_TRACE && urlLookup
      && isExplicitScannerTrace(alert?.rule?.description)) return reason;
  return null;
}

// This is an isolated training-layer deny store, not the production ZTNA policy.
// Only a gateway-supplied verifiedSourceIp is considered; request headers are not trusted.
export function createZtnaDenyLayer({ now = () => Date.now() } = {}) {
  const rules = new Map();

  function cleanup() {
    const time = now();
    for (const [id, rule] of rules) {
      if (Date.parse(rule.expiresAt) <= time) rules.delete(id);
    }
  }

  return {
    addDenyRule(rule) {
      if (!rule || rule.schema !== 'aleph.xdr.known-cve.deny.v1'
          || rule.action !== 'deny' || !checkedAddress(rule.match?.sourceIp)
          || !ALERT_ID.test(rule.evidenceAlertId ?? '')
          || typeof rule.reason !== 'string' || !Object.values(REASONS).includes(rule.reason)
          || !Number.isFinite(rule.confidence) || rule.confidence < 0.85 || rule.confidence > 1
          || !Number.isFinite(Date.parse(rule.createdAt)) || !Number.isFinite(Date.parse(rule.expiresAt))
          || Date.parse(rule.expiresAt) <= now()) {
        throw new Error('INVALID_XDR_DENY_RULE');
      }
      cleanup();
      rules.set(rule.id, structuredClone(rule));
    },
    checkAccess({ verifiedSourceIp } = {}) {
      cleanup();
      const sourceIp = checkedAddress(verifiedSourceIp);
      if (!sourceIp) return { action: 'continue', matchedRuleId: null };
      for (const rule of rules.values()) {
        if (rule.match.sourceIp === sourceIp) return { action: 'deny', matchedRuleId: rule.id };
      }
      return { action: 'continue', matchedRuleId: null };
    },
    listRules() {
      cleanup();
      return [...rules.values()].map((rule) => structuredClone(rule));
    },
  };
}

export function createResponder({
  ruleLayer = createZtnaDenyLayer(),
  logPath = DEFAULT_LOG_PATH,
  now = () => Date.now(),
  ttlMs = DEFAULT_TTL_MS,
} = {}) {
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 60_000 || ttlMs > 3_600_000) {
    throw new Error('INVALID_XDR_TTL');
  }
  if (!ruleLayer || typeof ruleLayer.addDenyRule !== 'function') {
    throw new Error('INVALID_XDR_RULE_LAYER');
  }

  async function logEvent(row) {
    await mkdir(dirname(logPath), { recursive: true });
    await appendFile(logPath, `${JSON.stringify(row)}\n`, 'utf8');
  }

  async function respond(alert, decision) {
    if (!safeDecision(decision)) throw new Error('INVALID_XDR_DECISION');
    if (decision.action === 'record') return { action: 'record', rule: null, rejection: null };

    const time = now();
    if (!Number.isFinite(time)) throw new Error('INVALID_XDR_CLOCK');
    const alertId = typeof alert?.id === 'string' && ALERT_ID.test(alert.id) ? alert.id : null;
    let action = 'alert';
    let rule = null;
    let rejection = null;

    if (decision.action === 'block') {
      const reason = verifiedReason(alert, decision.reason);
      const sourceIp = checkedAddress(alert?.data?.srcip);
      if (!reason) rejection = 'unverified_cve_evidence';
      else if (!alertId) rejection = 'invalid_alert_id';
      else if (!sourceIp) rejection = 'invalid_source_ip';
      else if (decision.confidence < 0.85) rejection = 'insufficient_confidence';
      else {
        rule = {
          schema: 'aleph.xdr.known-cve.deny.v1',
          id: `xdr-known-cve-${alertId}`,
          action: 'deny',
          match: { sourceIp },
          evidenceAlertId: alertId,
          reason,
          confidence: decision.confidence,
          createdAt: new Date(time).toISOString(),
          expiresAt: new Date(time + ttlMs).toISOString(),
        };
        await ruleLayer.addDenyRule(rule);
        action = 'block';
      }
    }

    await logEvent({
      at: new Date(time).toISOString(),
      alertId: alertId ?? 'unknown',
      action,
      confidence: decision.confidence,
      reason: action === 'block' ? rule.reason : (decision.action === 'alert'
        ? '알려진 취약점 악용 의심'
        : '검증되지 않은 차단 근거'),
      ...(rule ? { expiresAt: rule.expiresAt } : {}),
    });
    return { action, rule, rejection };
  }

  return { respond, ruleLayer };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  try {
    if (process.argv[2] !== '--fixture') {
      throw new Error('USAGE: node xdr/known-cve/respond.mjs --fixture');
    }
    const fixturePath = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'known-cve.json');
    const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
    if (fixture?.moduleKey !== 'known-cve' || !Array.isArray(fixture.alerts)) {
      throw new Error('INVALID_XDR_FIXTURE');
    }

    const { decide } = await import('./decide.mjs');
    const layer = createZtnaDenyLayer();
    const responder = createResponder({ ruleLayer: layer });
    const counts = { block: 0, alert: 0, record: 0 };
    let decisionBlocks = 0;
    let normalBlocked = 0;
    const rejectedBlocks = [];

    for (const alert of fixture.alerts) {
      const decision = decide(alert);
      if (decision.action === 'block') decisionBlocks += 1;
      const response = await responder.respond(alert, decision);
      counts[response.action] += 1;
      if (decision.action === 'block' && response.action !== 'block') {
        rejectedBlocks.push({ alertId: alert.id ?? 'unknown', rejection: response.rejection });
      }
      if (!hasT1190(alert?.rule?.mitre)
          && layer.checkAccess({ verifiedSourceIp: alert?.data?.srcip }).action === 'deny') {
        normalBlocked += 1;
      }
    }

    let testTime = 1_700_000_000_000;
    const expiryLayer = createZtnaDenyLayer({ now: () => testTime });
    expiryLayer.addDenyRule({
      schema: 'aleph.xdr.known-cve.deny.v1', id: 'expiry-check', action: 'deny',
      match: { sourceIp: '203.0.113.250' }, evidenceAlertId: 'expiry-check',
      reason: REASONS.HEADER_JNDI, confidence: 0.9,
      createdAt: new Date(testTime).toISOString(), expiresAt: new Date(testTime + 60_000).toISOString(),
    });
    testTime += 60_001;
    const expiryReleased = expiryLayer.checkAccess({ verifiedSourceIp: '203.0.113.250' }).action === 'continue';

    console.log(JSON.stringify({
      decisionBlocks,
      counts,
      temporaryDenyRules: layer.listRules().length,
      rejectedBlocks,
      normalBlocked,
      expiryReleased,
      note: '메모리 실습 계층 결과입니다. 운영 ZTNA나 외부 방화벽에는 적용하지 않습니다.',
    }, null, 2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'XDR_RESPOND_FAILED');
    process.exitCode = 1;
  }
}
