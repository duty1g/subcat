import { useCallback, useEffect, useState } from "react";

// Read/write a single URL query param (history.replaceState, preserves others).
export function useUrlState(key: string, initial: string) {
  const [value, setValue] = useState<string>(() => {
    const p = new URLSearchParams(window.location.search);
    return p.get(key) ?? initial;
  });

  const update = useCallback(
    (v: string) => {
      setValue(v);
      const p = new URLSearchParams(window.location.search);
      if (v === "" || v === initial) p.delete(key);
      else p.set(key, v);
      const qs = p.toString();
      window.history.replaceState({}, "", window.location.pathname + (qs ? "?" + qs : ""));
    },
    [key, initial]
  );

  // Keep state in sync when the user navigates back/forward.
  useEffect(() => {
    const onPop = () => {
      const p = new URLSearchParams(window.location.search);
      setValue(p.get(key) ?? initial);
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, [key, initial]);

  return [value, update] as const;
}
