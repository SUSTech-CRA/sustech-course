import { create } from 'zustand';

interface ChallengeState {
  open: boolean;
  request: () => Promise<void>;
  succeed: () => void;
  fail: () => void;
}

// 单飞：并发的 429 共享同一个挑战 Promise，只弹一个 Modal
let pending: { promise: Promise<void>; resolve: () => void; reject: (error: unknown) => void } | null =
  null;

export const useChallengeStore = create<ChallengeState>((set) => ({
  open: false,
  request: () => {
    if (!pending) {
      let resolve!: () => void;
      let reject!: (error: unknown) => void;
      const promise = new Promise<void>((res, rej) => {
        resolve = res;
        reject = rej;
      });
      pending = { promise, resolve, reject };
      set({ open: true });
    }
    return pending.promise;
  },
  succeed: () => {
    pending?.resolve();
    pending = null;
    set({ open: false });
  },
  fail: () => {
    pending?.reject(new Error('challenge cancelled'));
    pending = null;
    set({ open: false });
  },
}));
