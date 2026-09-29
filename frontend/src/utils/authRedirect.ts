type RedirectLocation = {
  pathname: string;
  search: string;
  hash: string;
};

const DEFAULT_REDIRECT = '/';
const AUTH_ENTRY_PATHS = new Set(['/signin', '/signup']);

export function normalizeAuthRedirect(value: string | null | undefined) {
  if (!value || !value.startsWith('/') || value.startsWith('//') || value.includes('\\')) {
    return DEFAULT_REDIRECT;
  }

  const path = value.split(/[?#]/)[0].replace(/\/$/, '') || DEFAULT_REDIRECT;
  if (AUTH_ENTRY_PATHS.has(path)) return DEFAULT_REDIRECT;

  return value;
}

export function getRedirectFromLocation(location: RedirectLocation) {
  return normalizeAuthRedirect(`${location.pathname}${location.search}${location.hash}`);
}

function buildAuthPath(pathname: '/signin' | '/signup', redirectTo: string | null | undefined) {
  const next = normalizeAuthRedirect(redirectTo);
  if (next === DEFAULT_REDIRECT) return pathname;

  const params = new URLSearchParams({ next });
  return `${pathname}?${params.toString()}`;
}

export function buildSignInPath(redirectTo: string | null | undefined) {
  return buildAuthPath('/signin', redirectTo);
}

export function buildSignUpPath(redirectTo: string | null | undefined) {
  return buildAuthPath('/signup', redirectTo);
}
