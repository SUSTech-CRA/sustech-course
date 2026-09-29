/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_SENTRY_DSN?: string;
  readonly VITE_SENTRY_TRACES_SAMPLE_RATE?: string;
  readonly VITE_APP_VERSION?: string;
  readonly VITE_ADSENSE_CLIENT?: string;
  readonly VITE_ADSENSE_SLOT?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

interface Window {
  MathJax?: {
    tex?: {
      inlineMath?: string[][];
      displayMath?: string[][];
    };
    svg?: {
      fontCache?: string;
    };
    typesetPromise?: (elements?: Array<HTMLElement | null>) => Promise<void>;
  };
}
