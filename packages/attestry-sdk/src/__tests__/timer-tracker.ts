// ─── Test helper: follow ONE specific setTimeout handle ────────────────────
//
// Timer assertions must never count global `setTimeout` / `clearTimeout`
// calls. Other code in the same worker arms and clears timers on its own
// schedule. A notable case is Node's built-in fetch (undici), which keeps
// internal timers running after any real-HTTP test. Under
// `vitest --sequence.shuffle` that lands inside an unrelated test's window
// and makes count-based assertions flaky.
//
// Instead, give the code under test a DISTINCTIVE delay, pick out the
// handle(s) `setTimeout` returned for exactly that delay, and check
// `clearTimeout` on that handle by IDENTITY. Plain `toHaveBeenCalledWith`
// would compare by deep equality.
//
// Not a test file (no `.test.ts`), so vitest does not collect it; `src/**/__tests__/**`
// is excluded from the build.

import { vi } from "vitest";

export interface TimerTracker {
  /** Handles returned by `setTimeout` calls armed with exactly `delayMs`, in call order. */
  armed(): unknown[];
  /** True once `clearTimeout` has been called with this exact handle (identity). */
  isCleared(handle: unknown): boolean;
  /** Restore the real `setTimeout` / `clearTimeout`. */
  restore(): void;
}

export function trackTimersWithDelay(delayMs: number): TimerTracker {
  const setSpy = vi.spyOn(globalThis, "setTimeout");
  const clearSpy = vi.spyOn(globalThis, "clearTimeout");
  return {
    armed: () =>
      setSpy.mock.calls.flatMap((call, i) =>
        call[1] === delayMs ? [setSpy.mock.results[i]?.value as unknown] : [],
      ),
    isCleared: (handle) => clearSpy.mock.calls.some((call) => call[0] === handle),
    restore: () => {
      setSpy.mockRestore();
      clearSpy.mockRestore();
    },
  };
}
