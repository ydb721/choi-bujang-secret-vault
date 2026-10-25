import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_LOG_PATH = join(dirname(dirname(fileURLToPath(import.meta.url))), 'alerts.log');
const DEFAULT_TTL_MS = 10 * 60 * 1000;
const ALERT_ID = /^[a-zA-Z0-9._-]{1,80}$/u;
const ACTIONS = new Set(['block', 'alert', 'record']);
const PATTERNS = Object.freeze([
  { name: '반복된 명시적 SQL 주입 구문 탐지', minimumRuleLevel: 10, minimumCount: 10 },
  { name: '반복된 명시적 스크립트 삽입 표식 탐지', minimumRuleLevel: 10, minimumCount: 9 },
  { name: '반복된 상위 경로 탐색 표식 탐지', minimumRuleLevel: 11, minimumCount: 8 },
  { name: '반복된 명령 구분자 주입 표식 탐지', minimumRuleLevel: 11, minimumCount: 10 },
]);

function checkedAddress(value) {
  if (typeof value !== 'string') return null;
  const address = value.trim();
  return isIP(address) ? address : null;
}

function positiveInteger(value) {
  if (typeof value !== 'string' && typeof value !== 'number') return 0;
  const text = String(value);
  if (!/^[0-9]{1,8}$/u.test(text)) return 0;
  const count = Number(text);
  return Number.isSafeInteger(count) && count > 0 ? count : 0;
}

function safeDecision(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
    && ACTIONS.has(value.action)
    && Number.isFinite(value.confidence) && value.confidence >= 0 && value.confidence <= 1
    && typeof value.reason === 'string' && value.reason.trim().length > 0;
}

function matchedPatternNames(alert) {
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const level = Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0;
  const count = positiveInteger(alert?.data?.count);
  const mitre = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1190');
  if (!description || !count || !mitre) return [];

  const evidence = [
    /(?:SQL\s*(?:구문|주입|표식|형식)|데이터베이스\s*조회.*이어\s*붙)/iu.test(description),
    /스크립트\s*(?:삽입|표식|형식)/u.test(description),
    /(?:경로.*(?:거슬러\s*올라|이탈)|상위\s*경로|\.\.\/).*표(?:식|기)/u.test(description),
    /명령\s*구분자.*표(?:식|기)/u.test(description),
  ];
  return PATTERNS.filter((pattern, index) => evidence[index]
    && level >= pattern.minimumRuleLevel && count >= pattern.minimumCount).map((pattern) => pattern.name);
}

function verifiedReason(alert, reason) {
  if (typeof reason !== 'string') return null;
  const supplied = reason.split(' / ');
  const expected = matchedPatternNames(alert);
  if (!supplied.length || supplied.some((name) => !PATTERNS.some((pattern) => pattern.name === name))) return null;
  if (new Set(supplied).size !== supplied.length || supplied.length !== expected.length) return null;
  return supplied.every((name) => expected.includes(name)) ? reason : null;
}

// This is an isolated training-layer deny store. A production gateway must supply
// a verified peer address; request-provided forwarding headers are never trusted here.
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
      if (!rule || rule.schema !== 'aleph.xdr.web-injection.deny.v1'
          || rule.action !== 'deny' || !checkedAddress(rule.match?.sourceIp)
          || !ALERT_ID.test(rule.evidenceAlertId ?? '')
          || typeof rule.reason !== 'string' || !Number.isFinite(rule.confidence)
          || rule.confidence < 0.85 || rule.confidence > 1
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
    const reason = verifiedReason(alert, decision.reason);
    let action = 'alert';
    let rule = null;
    let rejection = null;

    if (decision.action === 'block') {
      const sourceIp = checkedAddress(alert?.data?.srcip);
      if (!reason) rejection = 'unverified_pattern_reason';
      else if (!alertId) rejection = 'invalid_alert_id';
      else if (!sourceIp) rejection = 'invalid_source_ip';
      else if (decision.confidence < 0.85) rejection = 'insufficient_confidence';
      else {
        rule = {
          schema: 'aleph.xdr.web-injection.deny.v1',
          id: `xdr-web-injection-${alertId}`,
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

    const safeReason = reason ?? (decision.action === 'alert'
      ? '웹 주입 의심'
      : '검증되지 않은 차단 사유');
    await logEvent({
      at: new Date(time).toISOString(),
      alertId: alertId ?? 'unknown',
      action,
      confidence: decision.confidence,
      reason: safeReason,
      ...(rule ? { expiresAt: rule.expiresAt } : {}),
    });
    return { action, rule, rejection };
  }

  return { respond, ruleLayer };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  try {
    if (process.argv[2] !== '--fixture') throw new Error('USAGE: node xdr/web-injection/respond.mjs --fixture');
    const fixturePath = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'web-injection.json');
    const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
    if (fixture?.moduleKey !== 'web-injection' || !Array.isArray(fixture.alerts)) throw new Error('INVALID_XDR_FIXTURE');
    const { decide } = await import('./decide.mjs');
    const layer = createZtnaDenyLayer();
    const service = createResponder({ ruleLayer: layer });
    const counts = { block: 0, alert: 0, record: 0 };
    let candidateBlocks = 0;
    let normalBlocked = 0;
    const rejectedBlocks = [];
    for (const alert of fixture.alerts) {
      const decision = decide(alert);
      if (decision.action === 'block') candidateBlocks += 1;
      const response = await service.respond(alert, decision);
      counts[response.action] += 1;
      if (decision.action === 'block' && response.action !== 'block') {
        rejectedBlocks.push({ alertId: alert.id ?? 'unknown', rejection: response.rejection });
      }
      if (Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.length === 0
          && layer.checkAccess({ verifiedSourceIp: alert?.data?.srcip }).action === 'deny') {
        normalBlocked += 1;
      }
    }

    let testTime = 1_700_000_000_000;
    const expiryLayer = createZtnaDenyLayer({ now: () => testTime });
    expiryLayer.addDenyRule({
      schema: 'aleph.xdr.web-injection.deny.v1', id: 'expiry-check', action: 'deny',
      match: { sourceIp: '203.0.113.250' }, evidenceAlertId: 'expiry-check',
      reason: PATTERNS[0].name, confidence: 0.9,
      createdAt: new Date(testTime).toISOString(), expiresAt: new Date(testTime + 60_000).toISOString(),
    });
    testTime += 60_001;
    const expiryReleased = expiryLayer.checkAccess({ verifiedSourceIp: '203.0.113.250' }).action === 'continue';

    console.log(JSON.stringify({
      decisionBlocks: candidateBlocks,
      counts,
      temporaryDenyRules: layer.listRules().length,
      rejectedBlocks,
      normalBlocked,
      expiryReleased,
      note: '격리 실습 결과이며 기존 ZTNA 정책이나 운영 차단 상태를 뜻하지 않습니다.',
    }, null, 2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'XDR_RESPOND_FAILED');
    process.exitCode = 1;
  }
}
