import { message } from 'antd';
import axios, { AxiosError, type InternalAxiosRequestConfig } from 'axios';
import createAuthRefreshInterceptor from 'axios-auth-refresh';

import { queryClient } from '../queryClient';
import { useAuthStore } from '../stores/authStore';
import { useChallengeStore } from '../stores/challengeStore';
import type { TokenResponse } from '../types';

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

const refreshClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

const CHALLENGE_STORAGE_KEY = 'ncesnext-challenge-exempt';

let challengeExempt: { token: string; expiresAt: number } | null = (() => {
  try {
    const raw = sessionStorage.getItem(CHALLENGE_STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
})();

export function setChallengeExempt(token: string, expiresInSeconds: number) {
  challengeExempt = { token, expiresAt: Date.now() + expiresInSeconds * 1000 };
  try {
    sessionStorage.setItem(CHALLENGE_STORAGE_KEY, JSON.stringify(challengeExempt));
  } catch {
    // sessionStorage 不可用时凭证仅保留在内存中
  }
}

function getChallengeExemptToken(): string | null {
  if (challengeExempt && Date.now() < challengeExempt.expiresAt) {
    return challengeExempt.token;
  }
  return null;
}

apiClient.interceptors.request.use((config) => {
  const token = useAuthStore.getState().accessToken;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  const exemptToken = getChallengeExemptToken();
  if (exemptToken) {
    config.headers['X-Challenge-Token'] = exemptToken;
  }
  return config;
});

const refreshAuthLogic = async (failedRequest: AxiosError) => {
  const refreshToken = useAuthStore.getState().refreshToken;
  if (!refreshToken) {
    useAuthStore.getState().logout();
    queryClient.removeQueries();
    return Promise.reject(failedRequest);
  }

  try {
    const { data } = await refreshClient.post<TokenResponse>('/auth/refresh', {
      refresh_token: refreshToken,
    });
    useAuthStore.getState().setTokens(data.access_token, data.refresh_token);
    if (failedRequest.response?.config.headers) {
      failedRequest.response.config.headers.Authorization = `Bearer ${data.access_token}`;
    }
    return Promise.resolve();
  } catch (error) {
    // 仅在凭证确实失效（401）时登出；限流 429、网络错误或 5xx 不应清掉会话
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      useAuthStore.getState().logout();
      queryClient.removeQueries();
    }
    return Promise.reject(error);
  }
};

createAuthRefreshInterceptor(apiClient, refreshAuthLogic, {
  statusCodes: [401],
});

let lastRateLimitWarnAt = 0;

apiClient.interceptors.response.use(undefined, async (error) => {
  if (axios.isAxiosError(error) && error.response?.status === 429) {
    const config = error.config as
      | (InternalAxiosRequestConfig & { _challengeRetried?: boolean })
      | undefined;
    if (error.response.data?.challenge === 'turnstile' && config && !config._challengeRetried) {
      try {
        await useChallengeStore.getState().request();
        config._challengeRetried = true;
        return await apiClient.request(config);
      } catch {
        // 用户取消或验证失败，回落到普通 429 提示
      }
    }
    const now = Date.now();
    if (now - lastRateLimitWarnAt > 3000) {
      lastRateLimitWarnAt = now;
      message.warning('请求过于频繁，请稍后再试');
    }
  }
  return Promise.reject(error);
});

export function getApiErrorMessage(error: unknown, fallback = '请求失败，请稍后再试') {
  if (axios.isAxiosError(error)) {
    const detail = error.response?.data?.detail;
    if (typeof detail === 'string') return detail;
    if (Array.isArray(detail) && detail.length > 0) {
      return detail
        .map((item) => item?.msg || item?.message)
        .filter(Boolean)
        .join('；');
    }
    if (typeof error.response?.data?.message === 'string') return error.response.data.message;
    if (error.message) return error.message;
  }
  if (error instanceof Error) return error.message;
  return fallback;
}

export default apiClient;
