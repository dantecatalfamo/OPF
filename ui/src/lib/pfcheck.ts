// A quick client-side sanity check for hand-written pf lines. The
// appliance runs the real check (pfctl -nf) before anything is applied.
const starters = ['pass', 'block', 'match', 'anchor', 'antispoof', 'load', 'table', 'set', 'queue', '#'];

export function checkPfLine(text: string): string | null {
  const t = text.trim();
  if (!t) return 'Enter a pf rule';
  if (t.includes('\n')) return 'One rule per line; use custom pf blocks for several';
  const first = t.split(/\s+/)[0];
  if (!starters.some((s) => first === s || first.startsWith('#'))) return `pf rules start with pass, block or match, not “${first}”`;
  const pairs: Record<string, string> = { '{': '}', '(': ')' };
  const stack: string[] = [];
  let inQuote = false;
  for (const c of t) {
    if (c === '"') inQuote = !inQuote;
    if (inQuote) continue;
    if (c in pairs) stack.push(pairs[c]);
    else if (c === '}' || c === ')') {
      if (stack.pop() !== c) return `Unbalanced “${c}”`;
    }
  }
  if (inQuote) return 'Unclosed quote';
  if (stack.length) return `Missing “${stack[stack.length - 1]}”`;
  return null;
}

export function rawAction(text: string): 'pass' | 'block' | 'match' | 'reject' | 'other' {
  const t = text.trim();
  if (t.startsWith('block return')) return 'reject';
  const first = t.split(/\s+/)[0];
  return first === 'pass' || first === 'block' || first === 'match' ? first : 'other';
}
