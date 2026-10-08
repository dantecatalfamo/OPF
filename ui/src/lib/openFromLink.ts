import { useEffect } from 'react';
import { useSearchParams } from 'react-router';

/** Opens the item a link names with ?edit=<id> (a rule, a port forward),
 *  then drops the parameter so closing it leaves the page as it was. */
export function useOpenFromLink<T extends { id: string }>(items: T[], open: (item: T) => void) {
  const [params, setParams] = useSearchParams();
  const id = params.get('edit');
  useEffect(() => {
    if (!id) return;
    const item = items.find((i) => i.id === id);
    if (item) open(item);
    setParams((p) => { const n = new URLSearchParams(p); n.delete('edit'); return n; }, { replace: true });
  }, [id]); // eslint-disable-line react-hooks/exhaustive-deps
}
