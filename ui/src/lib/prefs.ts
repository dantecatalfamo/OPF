import { useState } from 'react';

// usePref is a choice this browser remembers (localStorage), for
// conveniences only: without storage it's the default every time.
export function usePref(key: string, initial: boolean): [boolean, (v: boolean) => void] {
  const [v, setV] = useState(() => {
    try {
      const s = localStorage.getItem(key);
      return s === null ? initial : s === '1';
    } catch {
      return initial;
    }
  });
  return [v, (nv) => {
    setV(nv);
    try {
      localStorage.setItem(key, nv ? '1' : '0');
    } catch {
      /* per-browser convenience only */
    }
  }];
}
