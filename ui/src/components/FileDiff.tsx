import { diffLines, type DiffLine } from '../lib/diff';

const CONTEXT = 3;

// Shows changed lines with a few lines of context, collapsing the rest.
export function FileDiff({ before, after }: { before: string; after: string }) {
  const lines = diffLines(before, after);
  const keep = lines.map(() => false);
  lines.forEach((l, i) => {
    if (l.kind !== 'same') {
      for (let j = Math.max(0, i - CONTEXT); j <= Math.min(lines.length - 1, i + CONTEXT); j++) keep[j] = true;
    }
  });
  const out: (DiffLine | { kind: 'gap'; count: number })[] = [];
  let skipped = 0;
  lines.forEach((l, i) => {
    if (keep[i]) {
      if (skipped) out.push({ kind: 'gap', count: skipped });
      skipped = 0;
      out.push(l);
    } else {
      skipped++;
    }
  });
  if (skipped) out.push({ kind: 'gap', count: skipped });

  return (
    <div className="diff">
      {out.map((l, i) =>
        l.kind === 'gap' ? (
          <div key={i} className="gap">
            {`  ⋯ ${l.count} unchanged line${l.count === 1 ? '' : 's'}`}
          </div>
        ) : (
          <div key={i} className={l.kind}>
            {(l.kind === 'add' ? '+ ' : l.kind === 'del' ? '− ' : '  ') + l.text}
          </div>
        ),
      )}
    </div>
  );
}
