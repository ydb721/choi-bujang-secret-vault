import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_LOG_PATH = join(dirname(dirname(fileURLToPath(import.meta.url))), 'alerts.log');
const DEFAULT_TTL_MS = 10 * 60 * 1000;
const ALERT_ID = /^[a-zA-Z0-9._-]{1,80}$/u;
const ACTIONS = new Set(['block', 'alert', 'record']);
const PATTERNS = Object.freeze([
  { name: '서명 없는 새 서비스 등록 또는 실행 파일 변경', technique: 'T1543', minimumRuleLevel: 10 },
  { name: '낯선 예약 작업의 임시 폴더 실행 파일', technique: 'T1053', minimumRuleLevel: 10 },
  { name: '시작 폴더 또는 시작 프로그램의 비정상 등록', technique: 'T1543/T1053', minimumRuleLevel: 10 },
  { name: '평소 목록에 없는 서비스의 재시작 지속 등록', technique: 'T1543', minimumRuleLevel: 10 },
]);

function checkedAddress(value) {
  if (typeof value !== 'string') return null;
  const address = value.trim();
  return isIP(address) ? address : null;
}

function text(value) {
  return typeof value === 'string' ? value : '';
}

function positiveInteger(value) {
  if (typeof value !== 'string' && typeof value !== 'number') return 0;
  const source = String(value);
  if (!/^\d{1,8}$/u.test(source)) return 0;
  const count = Number(source);
  return Number.isSafeInteger(count) && count > 0 ? count : 0;
}

function hasTechnique(mitre, technique) {
  return Array.isArray(mitre) && mitre.some((item) => item === technique);
}

function isTemporaryPath(path) {
  return /(?:^|[\\/])(?:temp|tmp)(?:[\\/]|$)|임시\s*폴더|temporary\s*(?:folder|directory)/iu.test(path);
}

function safeDecision(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
    && ACTIONS.has(value.action)
    && Number.isFinite(value.confidence) && value.confidence >= 0 && value.confidence <= 1
    && typeof value.reason === 'string' && value.reason.trim().length > 0;
}

function knownReason(value) {
  if (typeof value !== 'string') return false;
  const names = value.split(' / ');
  return names.length > 0 && new Set(names).size === names.length
    && names.every((name) => PATTERNS.some((pattern) => pattern.name === name));
}

function matchedPatternNames(alert) {
  const description = text(alert?.rule?.description);
  const path = text(alert?.data?.path);
  const level = typeof alert?.rule?.level === 'number' && Number.isFinite(alert.rule.level)
    ? alert.rule.level
    : 0;
  const count = positiveInteger(alert?.data?.count);
  const mitre = alert?.rule?.mitre;
  const service = /서비스|service/iu.test(description);
  const scheduledTask = /예약\s*작업|scheduled\s*task/iu.test(description);
  const startup = /시작\s*(?:폴더|프로그램|항목)|startup/iu.test(description);
  const unsigned = /서명(?:이|은|는)?\s*(?:없는|없(?:습니다|음|다)?|미확인)|unsigned/iu.test(description);
  const temporary = isTemporaryPath(path) || /임시\s*폴더|temporary\s*(?:folder|directory)/iu.test(description);
  const unfamiliarTask = /처음\s*보는|낯선|임의\s*문자열|random/iu.test(description);
  const newOrRegisteredService = /(?:새|신규).{0,20}서비스|서비스.{0,20}(?:등록|추가)|new\s+service|service\s+(?:registration|added)/iu.test(description);
  const executableChanged = /실행\s*파일.{0,20}(?:바뀌|변경)|(?:executable|binary).{0,20}(?:changed|modified)/iu.test(description);
  const repeatedRemoteRegistration = /원격\s*주소|remote/iu.test(description)
    && /서비스.{0,20}등록|service.{0,20}registration/iu.test(description)
    && count >= 3;
  const unexpectedStartup = /평소\s*목록에\s*없는|예상\s*밖|unexpected|unfamiliar/iu.test(description)
    && /추가|등록|added|registered/iu.test(description);
  const sharedTemporaryExecutable = scheduledTask && temporary
    && /같은.{0,20}임시|임시.{0,20}같은|shared.{0,20}temp/iu.test(description);
  const survivesRestart = /다시\s*켜도\s*남도록|재시작.{0,30}(?:남|등록)|surviv(?:e|es).{0,30}restart/iu.test(description);
  const unexpectedService = service && /평소\s*목록에\s*없는|unexpected|unfamiliar/iu.test(description);
  const matches = [];

  if (hasTechnique(mitre, 'T1543') && level >= PATTERNS[0].minimumRuleLevel
      && service && unsigned
      && ((newOrRegisteredService && temporary) || executableChanged || repeatedRemoteRegistration)) {
    matches.push(PATTERNS[0].name);
  }
  if (hasTechnique(mitre, 'T1053') && level >= PATTERNS[1].minimumRuleLevel
      && scheduledTask && unfamiliarTask && temporary) {
    matches.push(PATTERNS[1].name);
  }
  if ((hasTechnique(mitre, 'T1543') || hasTechnique(mitre, 'T1053'))
      && level >= PATTERNS[2].minimumRuleLevel && startup
      && (unexpectedStartup || sharedTemporaryExecutable)) {
    matches.push(PATTERNS[2].name);
  }
  if (hasTechnique(mitre, 'T1543') && level >= PATTERNS[3].minimumRuleLevel
      && unexpectedService && survivesRestart) {
    matches.push(PATTERNS[3].name);
  }
  return matches;
}

function verifiedReason(alert, reason) {
  if (typeof reason !== 'string') return null;
  const supplied = reason.split(' / ');
  const expected = matchedPatternNames(alert);
  if (!supplied.length || supplied.some((name) => !PATTERNS.some((pattern) => pattern.name === name))) {
    return null;
  }
  if (new Set(supplied).size !== supplied.length || supplied.length !== expected.length) return null;
  return supplied.every((name) => expected.includes(name)) ? reason : null;
}

// Isolated training-layer deny store. It does not modify the production ZTNA policy.
// A production gateway must supply the verified peer IP; alert.srcip is not gateway proof.
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
      if (!rule || rule.schema !== 'aleph.xdr.persistence.deny.v1'
          || rule.action !== 'deny' || !checkedAddress(rule.match?.sourceIp)
          || !ALERT_ID.test(rule.evidenceAlertId ?? '')
          || !knownReason(rule.reason)
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
      if (!reason) rejection = 'unverified_persistence_evidence';
      else if (!alertId) rejection = 'invalid_alert_id';
      else if (!sourceIp) rejection = 'invalid_source_ip';
      else if (decision.confidence < 0.85) rejection = 'insufficient_confidence';
      else {
        rule = {
          schema: 'aleph.xdr.persistence.deny.v1',
          id: `xdr-persistence-${alertId}`,
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
      reason: action === 'block' ? '검증된 지속성 공격 패턴' : (decision.action === 'alert'
        ? '지속성 의심 경보' : '검증되지 않은 차단 근거'),
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
      throw new Error('USAGE: node xdr/persistence/respond.mjs --fixture');
    }
    const fixturePath = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'persistence.json');
    const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
    if (fixture?.moduleKey !== 'persistence' || !Array.isArray(fixture.alerts)) {
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
      if (decision.action === 'record'
          && layer.checkAccess({ verifiedSourceIp: alert?.data?.srcip }).action === 'deny') {
        normalBlocked += 1;
      }
    }

    let testTime = 1_700_000_000_000;
    const expiryLayer = createZtnaDenyLayer({ now: () => testTime });
    expiryLayer.addDenyRule({
      schema: 'aleph.xdr.persistence.deny.v1', id: 'expiry-check', action: 'deny',
      match: { sourceIp: '203.0.113.250' }, evidenceAlertId: 'expiry-check',
      reason: PATTERNS[0].name, confidence: 0.9,
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
      sharedIpRisk: 'IP-only training rules can affect another user sharing a verified source IP.',
      note: '메모리 실습 계층 결과이며 운영 ZTNA나 방화벽에는 적용하지 않습니다.',
    }, null, 2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'XDR_RESPOND_FAILED');
    process.exitCode = 1;
  }
}
