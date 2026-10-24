// 제작 4 — 보너스 XDR의 독립 응답 계층.
// 기존 src/decider.mjs 및 policy/* 를 수정하지 않는다.
// 실제 ZTNA 엔진 연동 시에는 신뢰된 게이트웨이가 verifiedSourceIp와
// verifiedAccount를 제공하고, 별도 등록된 정책 인터페이스를 연결해야 한다.
import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_LOG_PATH = join(dirname(dirname(fileURLToPath(import.meta.url))), 'alerts.log');
const DEFAULT_TTL_MS = 10 * 60 * 1000;
const ACTIONS = new Set(['block', 'alert', 'record']);
const REASONS = new Set([
  '동일 주소·계정의 단시간 로그인 실패 반복',
  '여러 계정에 동일 비밀번호 대입',
]);
const ACCOUNT = /^[a-zA-Z0-9._@+\-]{1,64}$/u;
const ALERT_ID = /^[a-zA-Z0-9._\-]{1,80}$/u;

function checkedAddress(value) {
  if (typeof value !== 'string') return null;
  const addr = value.trim();
  return isIP(addr) ? addr : null;
}
function checkedAccount(value) {
  return typeof value === 'string' && ACCOUNT.test(value.trim()) ? value.trim() : null;
}
function accountScope(alert) {
  const first = checkedAccount(alert?.data?.srcuser);
  if (!first) return [];
  const raw = alert?.data?.accounts;
  const items = Array.isArray(raw) ? raw : typeof raw === 'string' ? raw.split(',') : [];
  // 비밀번호 원문을 보거나 기록하지 않는다. 요청 주체를 좁힐 계정명만 추출.
  const scope = [...new Set([first, ...items.map(checkedAccount).filter(Boolean)])];
  return scope.length <= 32 ? scope : [];
}
function safeDecision(value) {
  return Boolean(value) && typeof value === 'object' && ACTIONS.has(value.action)
    && Number.isFinite(value.confidence) && value.confidence >= 0 && value.confidence <= 1;
}
function trustedBruteForceEvidence(alert) {
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const count = Number(alert?.data?.count);
  const samePasswordAcrossAccounts = /(?:같은|동일)(?:\s*\S+){0,2}\s*비밀번호/u.test(description)
    && (/여러\s*계정|서로\s*다른\s*계정|계정\s*\d+\s*개/u.test(description)
      || Array.isArray(alert?.data?.accounts) && alert.data.accounts.length >= 8
      || typeof alert?.data?.accounts === 'string' && alert.data.accounts.split(',').length >= 8);
  const repeatedFailures = /실패/u.test(description) && Number.isFinite(count) && count >= 15;
  const explicitlyBenign = /로그인이 성공|뒤에 성공|로그아웃|상태가 유지|자료실 화면이 열렸/u.test(description);
  return Boolean(!explicitlyBenign && (repeatedFailures || samePasswordAcrossAccounts)
    && alert?.rule && Array.isArray(alert.rule.mitre)
    && alert.rule.mitre.some((id) => id === 'T1110' || /^T1110\.\d{3}$/u.test(id))
    && Number.isInteger(alert.rule.level) && alert.rule.level >= 9);
}

// ZTNA 앞단에 더하는 임시 거부 규칙 저장 계층(메모리 전용).
// 기존 판정기의 허용·추가인증·거부 판단을 바꾸지 않는다.
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
      if (!rule || rule.schema !== 'aleph.xdr.ztna.deny.v1'
          || rule.action !== 'deny' || !checkedAddress(rule.match?.sourceIp)
          || !Array.isArray(rule.match?.accounts) || !rule.match.accounts.length
          || !rule.match.accounts.every((account) => checkedAccount(account) === account)
          || !ALERT_ID.test(rule.evidenceAlertId ?? '')
          || !Number.isFinite(Date.parse(rule.expiresAt))
          || Date.parse(rule.expiresAt) <= now()) {
        throw new Error('INVALID_XDR_DENY_RULE');
      }
      cleanup();
      rules.set(rule.id, structuredClone(rule));
    },
    // 반드시 서버가 검증한 IP·인증 계정을 사용해야 한다.
    // 반환되는 continue는 XDR 거부 규칙에 해당하지 않는다는 뜻이지 ZTNA 허용이 아니다.
    checkAccess({ verifiedSourceIp, verifiedAccount } = {}) {
      cleanup();
      const ip = checkedAddress(verifiedSourceIp);
      const account = checkedAccount(verifiedAccount);
      if (!ip || !account) return { action: 'continue', matchedRuleId: null };
      for (const rule of rules.values()) {
        if (rule.match.sourceIp === ip && rule.match.accounts.includes(account)) {
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

// responder는 이미 계산된 decide(alert) 결과만 받아 실행한다.
// ruleLayer에는 실제 ZTNA가 제공하는 검증된 거부 규칙 등록 어댑터를 주입할 수 있다.
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
    throw new Error('INVALID_ZTNA_RULE_LAYER');
  }
  async function logEvent(row) {
    // 안전한 고정 필드만 기록. 원본 경보·비밀번호·토큰·설명 전문은 기록하지 않음.
    await mkdir(dirname(logPath), { recursive: true });
    await appendFile(logPath, `${JSON.stringify(row)}\n`, 'utf8');
  }
  async function respond(alert, decision) {
    if (!safeDecision(decision)) throw new Error('INVALID_XDR_DECISION');
    const action = decision.action;
    if (action === 'record') return { action: 'record', rule: null };

    const time = now();
    if (!Number.isFinite(time)) throw new Error('INVALID_XDR_CLOCK');
    const id = typeof alert?.id === 'string' && ALERT_ID.test(alert.id) ? alert.id : null;
    const reason = REASONS.has(decision.reason) ? decision.reason : '미확인 공격 패턴';
    const confidence = decision.confidence;
    let effective = 'alert';
    let rule = null;

    // 차단은 명백한 패턴 + 실제 근거 + 유효한 IP/계정 + 일치하는 확신도가 있어야 함.
    // 같은 IP를 공유하는 다른 정상 계정은 차단하지 않도록 계정 범위를 함께 제한.
    if (action === 'block' && confidence >= 0.85 && REASONS.has(reason)
        && id && trustedBruteForceEvidence(alert)) {
      const ip = checkedAddress(alert?.data?.srcip);
      const accounts = accountScope(alert);
      if (ip && accounts.length) {
        rule = {
          schema: 'aleph.xdr.ztna.deny.v1',
          id: `xdr-brute-force-${id}`,
          action: 'deny',
          match: { sourceIp: ip, accounts },
          evidenceAlertId: id,
          reason,
          confidence,
          createdAt: new Date(time).toISOString(),
          expiresAt: new Date(time + ttlMs).toISOString(),
        };
        // 실패 시 차단됐다고 보고하지 않으며 기존 정책에는 손대지 않음.
        await ruleLayer.addDenyRule(rule);
        effective = 'block';
      }
    }

    await logEvent({
      at: new Date(time).toISOString(),
      alertId: id ?? 'unknown',
      action: effective,
      confidence,
      reason,
      ...(rule ? { expiresAt: rule.expiresAt } : {}),
    });
    return { action: effective, rule };
  }
  return { respond, ruleLayer };
}

// 재현용 명령: node xdr/brute-force/respond.mjs --fixture
// 이 경로는 훈련용 경보만 사용하며 기존 판정기·운영 정책은 변경하지 않는다.
const isMain = process.argv[1]
  && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  try {
    if (process.argv[2] !== '--fixture') throw new Error('사용법: node xdr/brute-force/respond.mjs --fixture');
    const fixturePath = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'brute-force.json');
    const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
    if (fixture?.moduleKey !== 'brute-force' || !Array.isArray(fixture.alerts)) {
      throw new Error('INVALID_XDR_FIXTURE');
    }
    const { decide } = await import('./decide.mjs');
    const layer = createZtnaDenyLayer();
    const service = createResponder({ ruleLayer: layer });
    const counts = { block: 0, alert: 0, record: 0 };
    let normalBlocked = 0;
    for (const alert of fixture.alerts) {
      const response = await service.respond(alert, decide(alert));
      counts[response.action]++;
      if (Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.length === 0) {
        const checked = layer.checkAccess({
          verifiedSourceIp: alert?.data?.srcip,
          verifiedAccount: alert?.data?.srcuser,
        });
        if (checked.action === 'deny') normalBlocked++;
      }
    }
    console.log(JSON.stringify({
      counts,
      temporaryDenyRules: layer.listRules().length,
      normalBlocked,
      note: '격리 실습 결과. 기존 ZTNA 정책이나 운영 차단 상태를 뜻하지 않습니다.',
    }, null, 2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'XDR_RESPOND_FAILED');
    process.exitCode = 1;
  }
}
