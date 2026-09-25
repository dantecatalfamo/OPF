// Turns the single-file preview build into a page fragment (no
// <html>/<head>/<body>) for hosts that supply their own document shell.
import { readFileSync, writeFileSync } from 'node:fs';

const [src, dst] = process.argv.slice(2);
const html = readFileSync(src, 'utf8');
const head = html.match(/<head>([\s\S]*?)<\/head>/i)?.[1] ?? '';
const body = html.match(/<body>([\s\S]*?)<\/body>/i)?.[1] ?? '';
const title = head.match(/<title>[\s\S]*?<\/title>/i)?.[0] ?? '';
const assets = [...head.matchAll(/<(script|style)\b[\s\S]*?<\/\1>/gi)].map((m) => m[0]);
writeFileSync(dst, [title, ...assets.filter((a) => a.startsWith('<style')), body.trim(), ...assets.filter((a) => a.startsWith('<script'))].join('\n'));
console.log(`wrote ${dst}`);
