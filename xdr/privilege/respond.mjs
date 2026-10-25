import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_LOG_PATH = join(dirname(dirname(fileURLToPath(import.meta.url))), 'alerts.log');
const DEFAULT_TTL_MS = 10 * 60 * 1000;
const ALERT_ID = /^[a-zA-Z0-9._-]{1,80}$/u;
const ACCOUNT = /^[a-zA-Z0-9._@+\-]{1,64}$/u;
const ACTIONS = new Set(['block', 'alert', 'record']);
const PATTERNS = Object.freeze([
  '일반 계정의 관리자 그룹 추가 직후 관리자 명령 실행',
  '낯선 주소의 업무 시간 밖 관리자 명령 실행',
  '동일 출발 주소의 여러 계정 관리자 그룹 추가',
  '낯선 주소의 관리자 세션 권한 변경',
  '업무 외 시간 관리자 그룹 추가와 명령 실행 결합',
  '다른 계정 권한을 이용한 관리자 명령 실행',
  '제거 직후 관리자 그룹 재등록',
]);
const REMOTE_ADMIN_GROUP_ADDITION = '원격 주소의 일반 계정 관리자 그룹 추가';

function checkedAddress(value) {
  if (typeof value !== 'string') return null;
  const address = value.trim();
  return isIP(address) ? address : null;
}

function checkedAccount(value) {
  return typeof value === 'string' && ACCOUNT.test(value.trim()) ? value.trim() : null;
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

function isAdministrativeGroup(value) {
  return /^(?:administrators?|admin|관리자(?:\s*그룹)?)$/iu.test(text(value).trim());
}

function safeDecision(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
    && ACTIONS.has(value.action)
    && Number.isFinite(value.confidence) && value.confidence >= 0 && value.confidence <= 1
    && typeof value.reason === 'string' && value.reason.trim().length > 0;
}

function knownReason(value) {
  if (typeof value !== 'string') return false;
  if (value === REMOTE_ADMIN_GROUP_ADDITION) return true;
  const names = value.split(' / ');
  return names.length > 0 && new Set(names).size === names.length
    && names.every((name) => PATTERNS.includes(name));
}

function matchedPatternNames(alert) {
  const description = text(alert?.rule?.description);
  const group = text(alert?.data?.group);
  const level = typeof alert?.rule?.level === 'number' && Number.isFinite(alert.rule.level)
    ? alert.rule.level
    : 0;
  const count = positiveInteger(alert?.data?.count);
  const mitre = alert?.rule?.mitre;
  const t1068 = hasTechnique(mitre, 'T1068');
  const t1078 = hasTechnique(mitre, 'T1078');
  const cancelledOrFailed = /취소|실패|cancel(?:led)?|failed/iu.test(description);
  const saysNotAdminGroup = /관리자\s*그룹은?\s*아닙니다|not\s+(?:an?\s+)?administrative\s+group/iu.test(description);
  const adminGroup = !saysNotAdminGroup
    && (isAdministrativeGroup(group) || /관리자\s*그룹/iu.test(description));
  const groupAddition = /관리자\s*그룹.{0,30}(?:추가|들어|등록)|(?:추가|들어|등록).{0,30}관리자\s*그룹|added.{0,30}(?:administrator|admin).{0,30}group/iu.test(description);
  const adminCommand = /관리자\s*명령|권한\s*명령|관리자\s*그룹.{0,40}명령\s*실행|administrator\s+command|privileged\s+command/iu.test(description);
  const unfamiliarSource = /원격\s*주소|처음\s*보는\s*주소|낯선\s*주소|주소는\s*처음\s*봅|unfamiliar\s+(?:source|address)/iu.test(description);
  const outsideHours = /수업\s*시간\s*밖|업무처럼\s*보이지\s*않는\s*시각|업무\s*시간\s*밖|outside\s+(?:business|class)\s+hours/iu.test(description);
  const immediateOrNewAdmin = /방금\s*관리자가\s*된|곧바로|직후|바로|newly\s+(?:became|made)\s+(?:an?\s+)?admin/iu.test(description);
  const multiAccountSameSource = /같은\s*주소.*계정\s*\d+\s*개|same\s+(?:source|address).{0,30}(?:\d+\s+accounts|multiple\s+accounts)/iu.test(description)
    && count >= 4;
  const sessionAdminChanged = /세션.*관리자\s*권한.*(?:바뀌|변경)|session.{0,30}(?:administrator|admin).{0,30}(?:changed|elevated)/iu.test(description);
  const otherAccountAuthority = /다른\s*계정의\s*권한|other\s+account(?:'s)?\s+(?:authority|privilege)/iu.test(description);
  const rapidReaddition = /관리자\s*그룹에서\s*빠진.*(?:1\s*분|짧은\s*시간).{0,30}다시\s*관리자|removed.{0,30}admin.{0,30}(?:minute|short).{0,30}re-?add/iu.test(description);
  const matches = [];

  if ((t1068 || t1078) && level >= 10 && adminCommand && immediateOrNewAdmin && !cancelledOrFailed) {
    matches.push(PATTERNS[0]);
  }
  if (t1068 && level >= 10 && unfamiliarSource && outsideHours && adminCommand && !cancelledOrFailed) {
    matches.push(PATTERNS[1]);
  }
  if (t1078 && level >= 10 && adminGroup && multiAccountSameSource && !cancelledOrFailed) {
    matches.push(PATTERNS[2]);
  }
  if (t1068 && level >= 10 && sessionAdminChanged && unfamiliarSource && !cancelledOrFailed) {
    matches.push(PATTERNS[3]);
  }
  if ((t1068 || t1078) && level >= 10 && adminGroup && groupAddition
      && adminCommand && outsideHours && !cancelledOrFailed) {
    matches.push(PATTERNS[4]);
  }
  if (t1068 && level >= 10 && otherAccountAuthority && adminCommand && !cancelledOrFailed) {
    matches.push(PATTERNS[5]);
  }
  if (t1078 && level >= 10 && adminGroup && rapidReaddition && !cancelledOrFailed) {
    matches.push(PATTERNS[6]);
  }

  const remoteAdminGroupAddition = t1078 && level >= 10 && adminGroup
    && groupAddition && unfamiliarSource && !cancelledOrFailed;
  return { matches, remoteAdminGroupAddition };
}

function verifiedReason(alert, reason) {
  const evidence = matchedPatternNames(alert);
  if (reason === REMOTE_ADMIN_GROUP_ADDITION) {
    return evidence.matches.length === 0 && evidence.remoteAdminGroupAddition ? reason : null;
  }
  if (!knownReason(reason)) return null;
  const supplied = reason.split(' / ');
  if (supplied.length !== evidence.matches.length) return null;
  return supplied.every((name) => evidence.matches.includes(name)) ? reason : null;
}

// This isolated training layer does not alter the existing ZTNA policy.
// It only evaluates a gateway-supplied verified account/IP pair at access time.
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
      if (!rule || rule.schema !== 'aleph.xdr.privilege.deny.v1'
          || rule.action !== 'deny' || !checkedAddress(rule.match?.sourceIp)
          || !checkedAccount(rule.match?.account) || !ALERT_ID.test(rule.evidenceAlertId ?? '')
          || !knownReason(rule.reason)
          || !Number.isFinite(rule.confidence) || rule.confidence < 0.85 || rule.confidence > 1
          || !Number.isFinite(Date.parse(rule.createdAt)) || !Number.isFinite(Date.parse(rule.expiresAt))
          || Date.parse(rule.expiresAt) <= now()) {
        throw new Error('INVALID_XDR_DENY_RULE');
      }
      cleanup();
      rules.set(rule.id, structuredClone(rule));
    },
    checkAccess({ verifiedSourceIp, verifiedAccount } = {}) {
      cleanup();
      const sourceIp = checkedAddress(verifiedSourceIp);
      const account = checkedAccount(verifiedAccount);
      if (!sourceIp || !account) return { action: 'continue', matchedRuleId: null };
      for (const rule of rules.values()) {
        if (rule.match.sourceIp === sourceIp && rule.match.account === account) {
          return { action: 'deny', matchedRuleId: rule.id };
        }
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
      const account = checkedAccount(alert?.data?.srcuser);
      if (!reason) rejection = 'unverified_privilege_evidence';
      else if (!alertId) rejection = 'invalid_alert_id';
      else if (!account) rejection = 'invalid_account';
      else if (!sourceIp) rejection = 'invalid_source_ip';
      else if (decision.confidence < 0.85) rejection = 'insufficient_confidence';
      else {
        rule = {
          schema: 'aleph.xdr.privilege.deny.v1',
          id: `xdr-privilege-${alertId}`,
          action: 'deny',
          match: { sourceIp, account },
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
      reason: action === 'block' ? '검증된 권한 탈취 패턴' : (decision.action === 'alert'
        ? '권한 상승 의심 경보' : '검증되지 않은 차단 근거'),
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
      throw new Error('USAGE: node xdr/privilege/respond.mjs --fixture');
    }
    const fixturePath = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'privilege.json');
    const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
    if (fixture?.moduleKey !== 'privilege' || !Array.isArray(fixture.alerts)) {
      throw new Error('INVALID_XDR_FIXTURE');
    }

    const { decide } = await import('./decide.mjs');
    const layer = createZtnaDenyLayer();
    const responder = createResponder({ ruleLayer: layer });
    const counts = { block: 0, alert: 0, record: 0 };
    let decisionBlocks = 0;
    let normalBlocked = 0;
    let alertBlocked = 0;
    const rejectedBlocks = [];

    for (const alert of fixture.alerts) {
      const decision = decide(alert);
      if (decision.action === 'block') decisionBlocks += 1;
      const response = await responder.respond(alert, decision);
      counts[response.action] += 1;
      if (decision.action === 'block' && response.action !== 'block') {
        rejectedBlocks.push({ alertId: alert.id ?? 'unknown', rejection: response.rejection });
      }
      const access = layer.checkAccess({
        verifiedSourceIp: alert?.data?.srcip,
        verifiedAccount: alert?.data?.srcuser,
      });
      if (decision.action === 'record' && access.action === 'deny') normalBlocked += 1;
      if (decision.action === 'alert' && access.action === 'deny') alertBlocked += 1;
    }

    let testTime = 1_700_000_000_000;
    const expiryLayer = createZtnaDenyLayer({ now: () => testTime });
    expiryLayer.addDenyRule({
      schema: 'aleph.xdr.privilege.deny.v1', id: 'expiry-check', action: 'deny',
      match: { sourceIp: '203.0.113.250', account: 'expiry-user' }, evidenceAlertId: 'expiry-check',
      reason: PATTERNS[0], confidence: 0.9,
      createdAt: new Date(testTime).toISOString(), expiresAt: new Date(testTime + 60_000).toISOString(),
    });
    testTime += 60_001;
    const expiryReleased = expiryLayer.checkAccess({
      verifiedSourceIp: '203.0.113.250', verifiedAccount: 'expiry-user',
    }).action === 'continue';

    console.log(JSON.stringify({
      decisionBlocks,
      counts,
      temporaryDenyRules: layer.listRules().length,
      rejectedBlocks,
      normalBlocked,
      alertBlocked,
      expiryReleased,
      scope: 'account-and-verified-source-ip',
      note: '메모리 실습 계층 결과이며 운영 ZTNA·세션 회수에는 검증된 게이트웨이 신원 매핑이 필요합니다.',
    }, null, 2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'XDR_RESPOND_FAILED');
    process.exitCode = 1;
  }
}
