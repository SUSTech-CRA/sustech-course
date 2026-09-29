import type { UserResponse } from './user';

export interface LoginRequest {
  username: string;
  password: string;
  remember?: boolean;
}

export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
  confirm_password: string;
  turnstile_token?: string | null;
}

export interface AuthPublicConfig {
  turnstile_site_key: string;
  oauth_cra_enabled: boolean;
  oauth_cra_url: string;
}

export interface ChallengeResponse {
  exempt_token: string;
  expires_in: number;
}

export interface ForgotPasswordRequest {
  email: string;
  turnstile_token?: string | null;
}

export interface ResetPasswordRequest {
  token: string;
  password: string;
  confirm_password: string;
}

export interface ConfirmEmailRequest {
  token: string;
}

export interface ChangePasswordRequest {
  old_password: string;
  new_password: string;
  confirm_password: string;
}

export interface UsernameSuggestionResponse {
  username: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: 'bearer';
}

export interface AuthSession {
  user: UserResponse;
  access_token: string;
  refresh_token: string;
}
