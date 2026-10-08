// Checks the command palette's places (src/lib/nav.ts) against the
// pages, both ways, from their source:
//  - each place's address is a page's route; its tab (a route parameter
//    such as /network/routing/gateways, or ?tab=, ?tool=, ?log=) is one
//    of that page's tabs; its #anchor is a card's id in that page or in
//    what it imports; and it says which page it's on as the sidebar
//    names it;
//  - each tab a page has, and each card with an id, has a place.
// npm run check:places (and make test).
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { nav, places } from '../src/lib/nav.ts';

const src = resolve(dirname(fileURLToPath(import.meta.url)), '../src');
const read = (f: string) => readFileSync(f, 'utf8');
const problems: string[] = [];

// Tabs that aren't places, and why.
const notPlaces: Record<string, string> = {
  // A file's views (as it is, the staged change, a change outside OPF),
  // not somewhere to go.
  'pages/ConfigFiles.tsx now': 'a view of the file shown',
  'pages/ConfigFiles.tsx staged': 'a view of the file shown',
  'pages/ConfigFiles.tsx outside': 'a view of the file shown',
};

// ---------- the pages: routes, and the files their components are in ----------

const app = read(join(src, 'App.tsx'));
const imports = new Map<string, string>(); // component -> file, from App.tsx
for (const m of app.matchAll(/import \{ ([^}]+) \} from '\.\/(pages\/[A-Za-z]+)';/g)) {
  for (const name of m[1].split(',').map((s) => s.trim())) imports.set(name, `${m[2]}.tsx`);
}
const routes: { pattern: string[]; file: string }[] = [];
for (const m of app.matchAll(/<Route (?:index|path="([^"]+)") element=\{<([A-Za-z]+) \/>\}/g)) {
  const file = imports.get(m[2]);
  if (file) routes.push({ pattern: (m[1] ?? '').split('/').filter(Boolean), file });
}

// The route for a path, the static one first (as react-router ranks
// them), and the values of its parameters.
function route(path: string): { file: string; params: string[] } | undefined {
  const parts = path.split('/').filter(Boolean);
  const fits = routes
    .filter((r) => r.pattern.length === parts.length && r.pattern.every((p, i) => p.startsWith(':') || p === parts[i]))
    .sort((a, b) => a.pattern.filter((p) => p.startsWith(':')).length - b.pattern.filter((p) => p.startsWith(':')).length);
  const r = fits[0];
  return r && { file: r.file, params: r.pattern.flatMap((p, i) => (p.startsWith(':') ? [decodeURIComponent(parts[i])] : [])) };
}

// A file and every file under src it imports, transitively.
const closures = new Map<string, Set<string>>();
function closure(file: string): Set<string> {
  const seen = closures.get(file);
  if (seen) return seen;
  const out = new Set<string>([file]);
  closures.set(file, out);
  const text = read(join(src, file));
  for (const m of text.matchAll(/from '(\.{1,2}\/[^']+)'/g)) {
    const base = join(dirname(file), m[1]);
    const f = ['.tsx', '.ts'].map((x) => base + x).find((x) => existsSync(join(src, x)));
    if (f) for (const g of closure(f)) out.add(g);
  }
  return out;
}

// A page's tabs: <Tabs.Tab value="x">; value={CONST} with CONST a string
// in the file; and value={l.value} over a list in the file, whose
// entries' value: 'x' are the tabs. Tabs whose values are the model's
// own (an interface's id, a tunnel's) aren't places.
function tabs(file: string): string[] {
  const text = read(join(src, file));
  const out = new Set<string>();
  for (const m of text.matchAll(/<Tabs\.Tab\b[^>]*?\bvalue=(?:"([^"]+)"|\{([A-Za-z_.]+)\})/g)) {
    if (m[1]) { out.add(m[1]); continue; }
    const expr = m[2];
    const c = new RegExp(`const ${expr} = '([^']+)'`).exec(text);
    if (c) out.add(c[1]);
    else if (/^[a-z]\.value$/.test(expr)) for (const v of text.matchAll(/\{ value: '([^']+)', label:/g)) out.add(v[1]);
  }
  return [...out];
}

// Cards with an id, and the file each is in.
function cardIds(file: string): string[] {
  return [...read(join(src, file)).matchAll(/<Card\b[^>]*?\bid="([^"]+)"/g)].map((m) => m[1]);
}

// ---------- the sidebar's names for a page ----------

const items = nav.flatMap((g) => (g.to ? [{ label: g.label, group: '', to: g.to }] : g.items!.map((i) => ({ label: i.label, group: g.label, to: i.to }))));
function sidebarItem(path: string) {
  return items
    .filter((i) => (i.to === '/' ? path === '/' : path === i.to || path.startsWith(i.to + '/')))
    .sort((a, b) => b.to.length - a.to.length)[0];
}

// ---------- places against the pages ----------

const covered = new Set<string>(); // "file tab" and "file #id" a place reaches
for (const p of places) {
  const where = `place "${p.label}" (${p.to})`;
  const url = new URL(p.to, 'http://x');
  const r = route(url.pathname);
  if (!r) { problems.push(`${where}: no page has the route ${url.pathname}`); continue; }
  const pageTabs = tabs(r.file);
  const asked = [...r.params, ...url.searchParams.values()];
  const tab = asked.find((v) => pageTabs.includes(v));
  if (asked.length && !tab) problems.push(`${where}: ${r.file} has no tab ${asked.join(' or ')} (its tabs: ${pageTabs.join(', ') || 'none'})`);
  if (tab) covered.add(`${r.file} ${tab}`);
  const id = url.hash.slice(1);
  if (id) {
    const file = [...closure(r.file)].find((f) => cardIds(f).includes(id));
    if (!file) problems.push(`${where}: no card with id "${id}" in ${r.file} or what it imports`);
    else covered.add(`${file} #${id}`);
  }
  const item = sidebarItem(url.pathname);
  const names = item ? [item.label, ...(item.group ? [`${item.group} › ${item.label}`] : [])] : [];
  if (!names.some((n) => p.page === n || p.page.startsWith(`${n} › `))) {
    problems.push(`${where}: says it's on "${p.page}", but the sidebar calls its page ${names.map((n) => `"${n}"`).join(' or ') || '(nothing)'}`);
  }
}

// ---------- the pages against places ----------

const pageFiles = [...new Set(routes.map((r) => r.file))];
for (const file of pageFiles) {
  for (const tab of tabs(file)) {
    const key = `${file} ${tab}`;
    if (!covered.has(key) && !notPlaces[key]) problems.push(`${file}: tab "${tab}" has no place in src/lib/nav.ts`);
  }
}
const cardFiles = new Set(pageFiles.flatMap((f) => [...closure(f)]));
for (const file of cardFiles) {
  for (const id of cardIds(file)) {
    if (!covered.has(`${file} #${id}`)) problems.push(`${file}: card #${id} has no place in src/lib/nav.ts`);
  }
}

if (problems.length) {
  for (const p of problems) console.error(p);
  console.error(`\n${problems.length} problem${problems.length === 1 ? '' : 's'} with the command palette's places`);
  process.exit(1);
}
console.log(`${places.length} places match the pages' ${pageFiles.length} files`);
