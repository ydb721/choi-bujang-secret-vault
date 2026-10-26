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
  '낯선 외부 목적지의 대용량·다량 자료 전송',
  '업무 시간 밖 낯선 목적지의 압축 파일 반출',
  '동일 목적지의 반복 대용량 전송',
  '비정상 통로의 다량 자료 연속 전송',
  '업무 시간 밖 동일 목적지 반복 반출',
  '낯선 목적지의 압축 파일 연속 업로드',
  '자료실 전체의 외부 복사',
  '명령 통로의 대용량 반복 전송',
  '여러 낯선 목적지로 동일 압축 파일 반출',
]);

function text(value) {
  return typeof value === 'string' ? value : '';
}

function checkedAddress(value) {
  const address = text(value).trim();
  return isIP(address) ? address : null;
}

function checkedAccount(value) {
  const account = text(value).trim();
  return ACCOUNT.test(account) ? account : null;
}

function nonNegativeInteger(value) {
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) && value >= 0 ? value : null;
  }
  if (typeof value !== 'string' || !/^\d{1,15}$/u.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function hasTechnique(mitre, technique) {
  return Array.isArray(mitre) && mitre.includes(technique);
}

function isFailureOrNoTransfer(description) {
  return /전송\s*(?:이|을)?\s*(?:실패|없(?:습니다|음)|아직\s*없)|외부\s*전송\s*(?:은|이)?\s*(?:아직\s*)?없|전송\s*시도.*실패|failed\s+(?:transfer|upload)|no\s+(?:external\s+)?transfer/iu.test(description);
}

function hasCompletedTransfer(description) {
  if (isFailureOrNoTransfer(description)) return false;
  return /(?:자료|파일|압축\s*파일|메모|자료실).{0,50}(?:나갔|전송(?:됐|되었|했)|올라갔|업로드(?:됐|되었|했)|복사(?:됐|되었|했))|전송(?:이|은)?\s*(?:\d+\s*번|반복|연속)|(?:sent|transferred|uploaded|copied).{0,50}(?:file|data|archive|collection)/iu.test(description);
}

function matchedPatternNames(alert) {
  const description = text(alert?.rule?.description);
  const level = typeof alert?.rule?.level === 'number' && Number.isFinite(alert.rule.level)
    ? alert.rule.level
    : 0;
  const mitre = alert?.rule?.mitre;
  const dstip = checkedAddress(alert?.data?.dstip);
  const bytes = nonNegativeInteger(alert?.data?.bytes);
  const files = nonNegativeInteger(alert?.data?.files);
  const count = nonNegativeInteger(alert?.data?.count);
  const t1041 = hasTechnique(mitre, 'T1041');
  const t1048 = hasTechnique(mitre, 'T1048');
  const failedOrNoTransfer = isFailureOrNoTransfer(description) || bytes === 0;
  const completedTransfer = hasCompletedTransfer(description);
  const largeTransfer = bytes !== null && bytes >= 50_000_000;
  const manyFiles = files !== null && files >= 50;
  const repeated = count !== null && count >= 5;
  const unfamiliarDestination = /처음\s*보(?:는|던)\s*(?:목적지|주소)|낯선\s*(?:목적지|주소)|unfamiliar\s+(?:destination|address)/iu.test(description);
  const externalDestination = /외부\s*(?:주소|목적지)|external\s+destination/iu.test(description);
  const sameDestination = /같은\s*목적지|same\s+destination/iu.test(description);
  const outsideHours = /업무\s*시간\s*밖|수업\s*시간\s*밖|outside\s+(?:business|class)\s+hours/iu.test(description);
  const archive = /압축\s*파일|archive|compressed/iu.test(description);
  const continuous = /연속|반복|\d+번|continuous|repeated/iu.test(description);
  const unusualChannel = /평소(?:에)?\s*(?:쓰지|사용하지)\s*않던\s*(?:포트|통로)|비정상\s*(?:포트|통로)|unusual\s+(?:port|channel)/iu.test(description);
  const wholeCollection = /자료실\s*전체|전체.{0,30}(?:외부|복사)|whole\s+(?:repository|collection)/iu.test(description);
  const commandChannel = /명령\s*(?:및\s*)?제어\s*통로|명령\s*통로|command(?:\s*and\s*control)?\s*channel/iu.test(description);
  const multipleDestinations = /(?:목적지|주소)\s*(?:두\s*곳|여러\s*곳)|multiple\s+(?:destinations|addresses)/iu.test(description);
  const sameArchive = /같은\s*압축\s*파일|same\s+archive/iu.test(description);
  const explicitBatch = /(?:묶음|한\s*번에|다량|대용량|큰\s*파일|large\s+file|bulk)/iu.test(description);
  const matches = [];

  if ((t1041 || t1048) && level >= 10 && dstip && completedTransfer && !failedOrNoTransfer
      && unfamiliarDestination && largeTransfer && (manyFiles || explicitBatch)) {
    matches.push(PATTERNS[0]);
  }
  if (t1048 && level >= 10 && dstip && completedTransfer && !failedOrNoTransfer
      && outsideHours && archive && unfamiliarDestination && largeTransfer) {
    matches.push(PATTERNS[1]);
  }
  if (t1041 && level >= 10 && dstip && completedTransfer && !failedOrNoTransfer
      && sameDestination && continuous && largeTransfer && repeated) {
    matches.push(PATTERNS[2]);
  }
  if (t1048 && level >= 10 && dstip && completedTransfer && !failedOrNoTransfer
      && unusualChannel && largeTransfer && manyFiles) {
    matches.push(PATTERNS[3]);
  }
  if (t1048 && level >= 10 && dstip && completedTransfer && !failedOrNoTransfer
      && outsideHours && sameDestination && continuous && largeTransfer && repeated) {
    matches.push(PATTERNS[4]);
  }
  if (t1048 && level >= 10 && dstip && completedTransfer && !failedOrNoTransfer
      && archive && unfamiliarDestination && continuous && largeTransfer) {
    matches.push(PATTERNS[5]);
  }
  if (t1041 && level >= 10 && dstip && completedTransfer && !failedOrNoTransfer
      && wholeCollection && externalDestination && largeTransfer && manyFiles) {
    matches.push(PATTERNS[6]);
  }
  if (t1041 && level >= 10 && dstip && completedTransfer && !failedOrNoTransfer
      && commandChannel && explicitBatch && continuous && largeTransfer && repeated) {
    matches.push(PATTERNS[7]);
  }
  if (t1048 && level >= 10 && dstip && completedTransfer && !failedOrNoTransfer
      && multipleDestinations && sameArchive && archive && largeTransfer) {
    matches.push(PATTERNS[8]);
  }
  return matches;
}

function verifiedReason(alert, reason) {
  if (typeof reason !== 'string' || !reason.trim()) return null;
  const supplied = reason.split(' / ');
  const matches = matchedPatternNames(alert);
  if (!supplied.length || new Set(supplied).size !== supplied.length
      || supplied.length !== matches.length || !supplied.every((name) => PATTERNS.includes(name))) {
    return null;
  }
  return supplied.every((name) => matches.includes(name)) ? reason : null;
}

function knownReason(reason) {
  if (typeof reason !== 'string' || !reason.trim()) return false;
  const names = reason.split(' / ');
  return names.length > 0 && new Set(names).size === names.length
    && names.every((name) => PATTERNS.includes(name));
}

function safeDecision(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
    && ACTIONS.has(value.action)
    && Number.isFinite(value.confidence) && value.confidence >= 0 && value.confidence <= 1
    && typeof value.reason === 'string' && value.reason.trim().length > 0;
}

// This training layer only applies to a gateway-verified source/account/destination tuple.
// It does not modify the existing ZTNA policy or operate an external firewall.
export function createExfiltrationDenyLayer({ now = () => Date.now() } = {}) {
  const rules = new Map();

  function cleanup() {
    const time = now();
    for (const [id, rule] of rules) {
      if (Date.parse(rule.expiresAt) <= time) rules.delete(id);
    }
  }

  return {
    addDenyRule(rule) {
      if (!rule || rule.schema !== 'aleph.xdr.exfiltration.deny.v1'
          || rule.action !== 'deny' || !checkedAddress(rule.match?.sourceIp)
          || !checkedAddress(rule.match?.destinationIp) || !checkedAccount(rule.match?.account)
          || !ALERT_ID.test(rule.evidenceAlertId ?? '') || !knownReason(rule.reason)
          || !Number.isFinite(rule.confidence) || rule.confidence < 0.85 || rule.confidence > 1
          || !Number.isFinite(Date.parse(rule.createdAt)) || !Number.isFinite(Date.parse(rule.expiresAt))
          || Date.parse(rule.expiresAt) <= now()) {
        throw new Error('INVALID_XDR_DENY_RULE');
      }
      cleanup();
      rules.set(rule.id, structuredClone(rule));
    },
    checkDestination({ verifiedSourceIp, verifiedAccount, verifiedDestinationIp } = {}) {
      cleanup();
      const sourceIp = checkedAddress(verifiedSourceIp);
      const account = checkedAccount(verifiedAccount);
      const destinationIp = checkedAddress(verifiedDestinationIp);
      if (!sourceIp || !account || !destinationIp) return { action: 'continue', matchedRuleId: null };
      for (const rule of rules.values()) {
        if (rule.match.sourceIp === sourceIp && rule.match.account === account
            && rule.match.destinationIp === destinationIp) {
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
  ruleLayer = createExfiltrationDenyLayer(),
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
      const destinationIp = checkedAddress(alert?.data?.dstip);
      const account = checkedAccount(alert?.data?.srcuser);
      if (!reason) rejection = 'unverified_exfiltration_evidence';
      else if (!alertId) rejection = 'invalid_alert_id';
      else if (!sourceIp) rejection = 'invalid_source_ip';
      else if (!destinationIp) rejection = 'invalid_destination_ip';
      else if (!account) rejection = 'invalid_account';
      else if (decision.confidence < 0.85) rejection = 'insufficient_confidence';
      else {
        rule = {
          schema: 'aleph.xdr.exfiltration.deny.v1',
          id: `xdr-exfiltration-${alertId}`,
          action: 'deny',
          match: { sourceIp, account, destinationIp },
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
      reason: action === 'block' ? '검증된 자료 유출 공격 패턴'
        : (decision.action === 'alert' ? '자료 유출 의심 경보' : '검증되지 않은 차단 근거'),
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
      throw new Error('USAGE: node xdr/exfiltration/respond.mjs --fixture');
    }
    const fixturePath = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'exfiltration.json');
    const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
    if (fixture?.moduleKey !== 'exfiltration' || !Array.isArray(fixture.alerts)) {
      throw new Error('INVALID_XDR_FIXTURE');
    }

    const { decide } = await import('./decide.mjs');
    const layer = createExfiltrationDenyLayer();
    const responder = createResponder({ ruleLayer: layer });
    const counts = { block: 0, alert: 0, record: 0 };
    let decisionBlocks = 0;
    let normalBlocked = 0;
    let alertBlocked = 0;
    const rejectedBlocks = [];
    let firstBlockRule = null;

    for (const alert of fixture.alerts) {
      const decision = decide(alert);
      if (decision.action === 'block') decisionBlocks += 1;
      const response = await responder.respond(alert, decision);
      counts[response.action] += 1;
      if (response.rule && !firstBlockRule) firstBlockRule = response.rule;
      if (decision.action === 'block' && response.action !== 'block') {
        rejectedBlocks.push({ alertId: alert.id ?? 'unknown', rejection: response.rejection });
      }
      const access = layer.checkDestination({
        verifiedSourceIp: alert?.data?.srcip,
        verifiedAccount: alert?.data?.srcuser,
        verifiedDestinationIp: alert?.data?.dstip,
      });
      if (decision.action === 'record' && access.action === 'deny') normalBlocked += 1;
      if (decision.action === 'alert' && access.action === 'deny') alertBlocked += 1;
    }

    const scopeChecks = firstBlockRule ? {
      exactTupleDenied: layer.checkDestination({
        verifiedSourceIp: firstBlockRule.match.sourceIp,
        verifiedAccount: firstBlockRule.match.account,
        verifiedDestinationIp: firstBlockRule.match.destinationIp,
      }).action === 'deny',
      sameSourceOtherDestinationContinues: layer.checkDestination({
        verifiedSourceIp: firstBlockRule.match.sourceIp,
        verifiedAccount: firstBlockRule.match.account,
        verifiedDestinationIp: '198.51.100.254',
      }).action === 'continue',
      sameDestinationOtherIdentityContinues: layer.checkDestination({
        verifiedSourceIp: '198.51.100.254',
        verifiedAccount: 'other-user',
        verifiedDestinationIp: firstBlockRule.match.destinationIp,
      }).action === 'continue',
    } : null;

    let testTime = 1_700_000_000_000;
    const expiryLayer = createExfiltrationDenyLayer({ now: () => testTime });
    expiryLayer.addDenyRule({
      schema: 'aleph.xdr.exfiltration.deny.v1', id: 'expiry-check', action: 'deny',
      match: { sourceIp: '203.0.113.250', account: 'expiry-user', destinationIp: '198.51.100.250' },
      evidenceAlertId: 'expiry-check', reason: PATTERNS[0], confidence: 0.9,
      createdAt: new Date(testTime).toISOString(), expiresAt: new Date(testTime + 60_000).toISOString(),
    });
    testTime += 60_001;
    const expiryReleased = expiryLayer.checkDestination({
      verifiedSourceIp: '203.0.113.250', verifiedAccount: 'expiry-user', verifiedDestinationIp: '198.51.100.250',
    }).action === 'continue';

    console.log(JSON.stringify({
      decisionBlocks,
      counts,
      blockedAlerts: counts.block,
      temporaryDenyRules: layer.listRules().length,
      rejectedBlocks,
      normalBlocked,
      alertBlocked,
      expiryReleased,
      scope: 'source-account-destination tuple',
      scopeChecks,
      note: '메모리 실습 계층 결과이며 운영 차단에는 신뢰된 게이트웨이의 검증된 신원·목적지·세션 매핑이 필요합니다.',
    }, null, 2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'XDR_RESPOND_FAILED');
    process.exitCode = 1;
  }
}
