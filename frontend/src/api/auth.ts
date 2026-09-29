import apiClient from './client';
import type {
  AuthPublicConfig,
  ChangePasswordRequest,
  ConfirmEmailRequest,
  ForgotPasswordRequest,
  LoginRequest,
  MessageResponse,
  RegisterRequest,
  ResetPasswordRequest,
  TokenResponse,
  UsernameSuggestionResponse,
  UserResponse,
} from '../types';

export const authApi = {
  async publicConfig() {
    const { data } = await apiClient.get<AuthPublicConfig>('/auth/public-config');
    return data;
  },

  async login(payload: LoginRequest) {
    const { data } = await apiClient.post<TokenResponse>('/auth/login', payload);
    return data;
  },

  async register(payload: RegisterRequest) {
    const { data } = await apiClient.post<UserResponse>('/auth/register', payload);
    return data;
  },

  async suggestUsername() {
    const { data } = await apiClient.get<UsernameSuggestionResponse>('/auth/suggest-username');
    return data;
  },

  async confirmEmail(payload: ConfirmEmailRequest) {
    const { data } = await apiClient.post('/auth/confirm-email', payload);
    return data;
  },

  async resendConfirmation(login: string) {
    const { data } = await apiClient.post<MessageResponse>('/auth/resend-confirmation', { login });
    return data;
  },

  async forgotPassword(payload: ForgotPasswordRequest) {
    const { data } = await apiClient.post('/auth/forgot-password', payload);
    return data;
  },

  async resetPassword(payload: ResetPasswordRequest) {
    const { data } = await apiClient.post('/auth/reset-password', payload);
    return data;
  },

  async me() {
    const { data } = await apiClient.get<UserResponse>('/auth/me');
    return data;
  },

  async changePassword(payload: ChangePasswordRequest) {
    const { data } = await apiClient.post<TokenResponse>('/auth/change-password', payload);
    return data;
  },

  async refresh(refreshToken: string) {
    const { data } = await apiClient.post<TokenResponse>('/auth/refresh', {
      refresh_token: refreshToken,
    });
    return data;
  },

  async logout(refreshToken: string) {
    await apiClient.post('/auth/logout', {
      refresh_token: refreshToken,
    });
  },
};
