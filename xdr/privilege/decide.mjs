// Mirrors patterns.json so this module remains standalone for the evaluator.
const PATTERNS = Object.freeze({
  NEW_ADMIN_COMMAND: '일반 계정의 관리자 그룹 추가 직후 관리자 명령 실행',
  OFF_HOURS_UNFAMILIAR_COMMAND: '낯선 주소의 업무 시간 밖 관리자 명령 실행',
  MULTI_ACCOUNT_ADMIN_ADDITION: '동일 출발 주소의 여러 계정 관리자 그룹 추가',
  UNFAMILIAR_SESSION_CHANGE: '낯선 주소의 관리자 세션 권한 변경',
  OFF_HOURS_GROUP_AND_COMMAND: '업무 외 시간 관리자 그룹 추가와 명령 실행 결합',
  OTHER_ACCOUNT_COMMAND: '다른 계정 권한을 이용한 관리자 명령 실행',
  RAPID_ADMIN_READD: '제거 직후 관리자 그룹 재등록',
});

const REMOTE_ADMIN_GROUP_ADDITION = '원격 주소의 일반 계정 관리자 그룹 추가';
const NO_MATCH = Object.freeze({
  action: 'record',
  confidence: 0,
  reason: '권한 탈취 근거 없음',
});

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

function hasPrivilegeTechnique(mitre) {
  return hasTechnique(mitre, 'T1068') || hasTechnique(mitre, 'T1078');
}

function isAdministrativeGroup(value) {
  return /^(?:administrators?|admin|관리자(?:\s*그룹)?)$/iu.test(text(value).trim());
}

function isExplicitNormal(description) {
  return /(?:수업용\s*)?관리\s*계정.*평소\s*주소.*로그인|그룹\s*소속을\s*읽기만|비밀번호를\s*변경|자기\s*세션\s*정보를\s*조회|평소\s*예약\s*작업을\s*확인|(?:existing|approved)\s+administrator.*usual\s+(?:address|login)|read[- ]only\s+(?:group|session)/iu.test(description);
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) return NO_MATCH;

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
  const noPrivilegeChange = /변경은\s*없|권한\s*상승\s*창.*취소|명령은\s*없|read[- ]only/iu.test(description);
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

  // Evaluate concrete privilege-takeover evidence before normal-context wording.
  const matches = [];
  if ((t1068 || t1078) && level >= 10 && adminCommand && immediateOrNewAdmin && !cancelledOrFailed) {
    matches.push(PATTERNS.NEW_ADMIN_COMMAND);
  }
  if (t1068 && level >= 10 && unfamiliarSource && outsideHours && adminCommand && !cancelledOrFailed) {
    matches.push(PATTERNS.OFF_HOURS_UNFAMILIAR_COMMAND);
  }
  if (t1078 && level >= 10 && adminGroup && multiAccountSameSource && !cancelledOrFailed) {
    matches.push(PATTERNS.MULTI_ACCOUNT_ADMIN_ADDITION);
  }
  if (t1068 && level >= 10 && sessionAdminChanged && unfamiliarSource && !cancelledOrFailed) {
    matches.push(PATTERNS.UNFAMILIAR_SESSION_CHANGE);
  }
  if ((t1068 || t1078) && level >= 10 && adminGroup && groupAddition
      && adminCommand && outsideHours && !cancelledOrFailed) {
    matches.push(PATTERNS.OFF_HOURS_GROUP_AND_COMMAND);
  }
  if (t1068 && level >= 10 && otherAccountAuthority && adminCommand && !cancelledOrFailed) {
    matches.push(PATTERNS.OTHER_ACCOUNT_COMMAND);
  }
  if (t1078 && level >= 10 && adminGroup && rapidReaddition && !cancelledOrFailed) {
    matches.push(PATTERNS.RAPID_ADMIN_READD);
  }

  if (matches.length) {
    return {
      action: 'block',
      confidence: matches.length > 1 ? 0.96 : 0.91,
      reason: matches.join(' / '),
    };
  }

  // A remote administrative-group addition is a completed privilege change even without a command.
  if (t1078 && level >= 10 && adminGroup && groupAddition && unfamiliarSource && !cancelledOrFailed) {
    return { action: 'block', confidence: 0.89, reason: REMOTE_ADMIN_GROUP_ADDITION };
  }

  if (isExplicitNormal(description)) return NO_MATCH;

  if (hasPrivilegeTechnique(mitre)) {
    return {
      action: 'alert',
      confidence: noPrivilegeChange ? 0.55 : 0.6,
      reason: 'T1068/T1078 경보: 자동 차단 근거가 부족한 권한 상승 의심',
    };
  }

  return NO_MATCH;
}
