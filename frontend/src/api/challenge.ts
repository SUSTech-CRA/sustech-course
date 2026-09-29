import axios from 'axios';

import type { ChallengeResponse } from '../types';
import { API_BASE_URL } from './client';

// 独立实例，不带拦截器：挑战请求本身再触发挑战流程会死锁
const challengeClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export async function solveChallenge(turnstileToken: string | null) {
  const { data } = await challengeClient.post<ChallengeResponse>('/challenge', {
    turnstile_token: turnstileToken,
  });
  return data;
}
