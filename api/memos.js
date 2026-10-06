import { verifyLogin } from '../src/verify-login.mjs';

export default async function handler(req, res) {
  try {
    const authHeader = req.headers.authorization;
    const user = await verifyLogin(authHeader);

    if (!user) {
      return res.status(401).json({ error: '인증에 실패했습니다.' });
    }

    if (req.method === 'GET') {
      // 정상 인증된 경우 메모 데이터 반환
      return res.status(200).json([
        { id: '1', title: '가상 메모 1', content: '보호된 자료 내용입니다.' }
      ]);
    }

    return res.status(405).json({ error: '허용되지 않는 메서드입니다.' });
  } catch (error) {
    return res.status(401).json({ error: '유효하지 않은 토큰입니다.' });
  }
}
