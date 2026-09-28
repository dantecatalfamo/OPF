export interface DiffLine {
  kind: 'same' | 'add' | 'del';
  text: string;
}

// Line diff via longest common subsequence. Config files are small.
export function diffLines(a: string, b: string): DiffLine[] {
  const x = a.split('\n');
  const y = b.split('\n');
  const n = x.length;
  const m = y.length;
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i][j] = x[i] === y[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (x[i] === y[j]) {
      out.push({ kind: 'same', text: x[i] });
      i++;
      j++;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      out.push({ kind: 'del', text: x[i++] });
    } else {
      out.push({ kind: 'add', text: y[j++] });
    }
  }
  while (i < n) out.push({ kind: 'del', text: x[i++] });
  while (j < m) out.push({ kind: 'add', text: y[j++] });
  return out;
}

// A unified diff with three lines of context, like diff -u, for the
// offline preview's stand-in backend.
export function unifiedDiff(a: string, b: string, labelA: string, labelB: string): string {
  const lines = diffLines(a, b);
  if (!lines.some((l) => l.kind !== 'same')) return '';
  const keep = lines.map(() => false);
  lines.forEach((l, i) => {
    if (l.kind !== 'same') for (let j = Math.max(0, i - 3); j <= Math.min(lines.length - 1, i + 3); j++) keep[j] = true;
  });
  const out = [`--- ${labelA}`, `+++ ${labelB}`];
  let inHunk = false;
  lines.forEach((l, i) => {
    if (!keep[i]) {
      inHunk = false;
      return;
    }
    if (!inHunk) out.push('@@');
    inHunk = true;
    out.push((l.kind === 'add' ? '+' : l.kind === 'del' ? '-' : ' ') + l.text);
  });
  return out.join('\n') + '\n';
}
