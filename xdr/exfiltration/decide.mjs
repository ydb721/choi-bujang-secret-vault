// Mirrors patterns.json so this module remains standalone for the evaluator.
const PATTERNS = Object.freeze({
  UNFAMILIAR_BULK: '낯선 외부 목적지의 대용량·다량 자료 전송',
  OFF_HOURS_ARCHIVE: '업무 시간 밖 낯선 목적지의 압축 파일 반출',
  REPEATED_SAME_DESTINATION: '동일 목적지의 반복 대용량 전송',
  UNUSUAL_CHANNEL_BULK: '비정상 통로의 다량 자료 연속 전송',
  OFF_HOURS_REPEATED: '업무 시간 밖 동일 목적지 반복 반출',
  CONTINUOUS_ARCHIVE_UPLOAD: '낯선 목적지의 압축 파일 연속 업로드',
  WHOLE_COLLECTION_COPY: '자료실 전체의 외부 복사',
  COMMAND_CHANNEL_REPEATED: '명령 통로의 대용량 반복 전송',
  MULTI_DESTINATION_ARCHIVE: '여러 낯선 목적지로 동일 압축 파일 반출',
});

const NO_MATCH = Object.freeze({
  action: 'record',
  confidence: 0,
  reason: '명확한 자료 유출 근거 없음',
});

function text(value) {
  return typeof value === 'string' ? value : '';
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

function hasExfiltrationTechnique(mitre) {
  return hasTechnique(mitre, 'T1041') || hasTechnique(mitre, 'T1048');
}

function isFailureOrNoTransfer(description) {
  return /전송\s*(?:이|을)?\s*(?:실패|없(?:습니다|음)|아직\s*없)|외부\s*전송\s*(?:은|이)?\s*(?:아직\s*)?없|전송\s*시도.*실패|failed\s+(?:transfer|upload)|no\s+(?:external\s+)?transfer/iu.test(description);
}

function hasCompletedTransfer(description) {
  if (isFailureOrNoTransfer(description)) return false;
  return /(?:자료|파일|압축\s*파일|메모|자료실).{0,50}(?:나갔|전송(?:됐|되었|했)|올라갔|업로드(?:됐|되었|했)|복사(?:됐|되었|했))|전송(?:이|은)?\s*(?:\d+\s*번|반복|연속)|(?:sent|transferred|uploaded|copied).{0,50}(?:file|data|archive|collection)/iu.test(description);
}

function isExplicitBenign(description) {
  return /수업\s*자료\s*주소.{0,40}(?:작은|소규모).{0,40}(?:동기화|sync).{0,40}(?:끝|완료)|(?:내\s*메모|반\s*공지|검색\s*결과|화면\s*새로고침|첨부\s*그림|세션\s*확인|로그아웃|다음\s*수업\s*공지).{0,40}(?:읽|받|열|저장|확인|새로고침|로그아웃)|(?:small|routine).{0,30}(?:class|course).{0,30}(?:sync|synchronization)/iu.test(description);
}

function isSuspiciousTransferSignal(description, bytes) {
  return /처음\s*보(?:는|던)\s*(?:목적지|주소)|낯선\s*(?:목적지|주소)|평소(?:와|보다).*(?:다른|높|늘)|압축\s*파일|백업처럼|명령\s*통로|전송\s*시도|전송\s*이\s*실패|파일\s*수.{0,20}(?:늘|증가)|자료\s*\d+건.{0,40}전송|unfamiliar\s+(?:destination|address)|failed\s+transfer|archive\s+(?:created|upload)/iu.test(description)
    || (bytes !== null && bytes > 0 && /전송|업로드|복사|나갔/iu.test(description));
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) return NO_MATCH;

  const description = text(alert?.rule?.description);
  const level = typeof alert?.rule?.level === 'number' && Number.isFinite(alert.rule.level)
    ? alert.rule.level
    : 0;
  const mitre = alert?.rule?.mitre;
  const dstip = text(alert?.data?.dstip).trim();
  const bytes = nonNegativeInteger(alert?.data?.bytes);
  const files = nonNegativeInteger(alert?.data?.files);
  const count = nonNegativeInteger(alert?.data?.count);
  const t1041 = hasTechnique(mitre, 'T1041');
  const t1048 = hasTechnique(mitre, 'T1048');
  const hasTechniqueContext = t1041 || t1048;
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

  // Concrete transfer evidence always takes priority over educational wording.
  const matches = [];
  if (hasTechniqueContext && level >= 10 && dstip && completedTransfer && !failedOrNoTransfer
      && unfamiliarDestination && largeTransfer && (manyFiles || explicitBatch)) {
    matches.push(PATTERNS.UNFAMILIAR_BULK);
  }
  if (t1048 && level >= 10 && dstip && completedTransfer && !failedOrNoTransfer
      && outsideHours && archive && unfamiliarDestination && largeTransfer) {
    matches.push(PATTERNS.OFF_HOURS_ARCHIVE);
  }
  if (t1041 && level >= 10 && dstip && completedTransfer && !failedOrNoTransfer
      && sameDestination && continuous && largeTransfer && repeated) {
    matches.push(PATTERNS.REPEATED_SAME_DESTINATION);
  }
  if (t1048 && level >= 10 && dstip && completedTransfer && !failedOrNoTransfer
      && unusualChannel && largeTransfer && manyFiles) {
    matches.push(PATTERNS.UNUSUAL_CHANNEL_BULK);
  }
  if (t1048 && level >= 10 && dstip && completedTransfer && !failedOrNoTransfer
      && outsideHours && sameDestination && continuous && largeTransfer && repeated) {
    matches.push(PATTERNS.OFF_HOURS_REPEATED);
  }
  if (t1048 && level >= 10 && dstip && completedTransfer && !failedOrNoTransfer
      && archive && unfamiliarDestination && continuous && largeTransfer) {
    matches.push(PATTERNS.CONTINUOUS_ARCHIVE_UPLOAD);
  }
  if (t1041 && level >= 10 && dstip && completedTransfer && !failedOrNoTransfer
      && wholeCollection && externalDestination && largeTransfer && manyFiles) {
    matches.push(PATTERNS.WHOLE_COLLECTION_COPY);
  }
  if (t1041 && level >= 10 && dstip && completedTransfer && !failedOrNoTransfer
      && commandChannel && explicitBatch && continuous && largeTransfer && repeated) {
    matches.push(PATTERNS.COMMAND_CHANNEL_REPEATED);
  }
  if (t1048 && level >= 10 && dstip && completedTransfer && !failedOrNoTransfer
      && multipleDestinations && sameArchive && archive && largeTransfer) {
    matches.push(PATTERNS.MULTI_DESTINATION_ARCHIVE);
  }

  if (matches.length) {
    return {
      action: 'block',
      confidence: matches.length > 1 ? 0.96 : 0.91,
      reason: matches.join(' / '),
    };
  }

  // Explicitly benign activity is recorded only after concrete attack evidence is evaluated.
  if (isExplicitBenign(description)) {
    return { action: 'record', confidence: 0.1, reason: '명시적인 정상 조회·동기화 활동' };
  }

  if (hasTechniqueContext && failedOrNoTransfer) {
    return { action: 'alert', confidence: 0.6, reason: '실패했거나 완료 근거가 없는 자료 전송 시도' };
  }
  if (hasTechniqueContext && archive && !completedTransfer) {
    return { action: 'alert', confidence: 0.58, reason: '외부 전송 없는 압축 파일 생성·준비 행위' };
  }
  if (hasTechniqueContext && commandChannel && !largeTransfer) {
    return { action: 'alert', confidence: 0.6, reason: '명령 통로의 소량 자료 관찰' };
  }
  if (hasTechniqueContext && isSuspiciousTransferSignal(description, bytes)) {
    return { action: 'alert', confidence: 0.6, reason: '추가 확인이 필요한 자료 유출 의심 신호' };
  }

  return NO_MATCH;
}
