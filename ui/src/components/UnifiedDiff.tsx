// Renders a unified diff (diff -u output) with added and removed lines
// coloured.
export function UnifiedDiff({ diff }: { diff: string }) {
  const lines = diff.replace(/\n$/, '').split('\n');
  return (
    <div className="diff">
      {lines.map((l, i) => {
        const kind = l.startsWith('+++') || l.startsWith('---') ? 'gap' : l.startsWith('@@') ? 'gap' : l.startsWith('+') ? 'add' : l.startsWith('-') ? 'del' : '';
        return (
          <div key={i} className={kind}>
            {l.startsWith('@@') ? '  ⋯' : l || ' '}
          </div>
        );
      })}
    </div>
  );
}
