// The Go generators, validation and pf parser compiled to WebAssembly
// (cmd/opfwasm): the offline preview build, which has no server to ask,
// runs on them, and the real UI uses them for previews of a large model
// (lib/generated.ts), so editing doesn't send the whole model to the
// firewall on every keystroke. The module is only fetched when first
// called.
import '../wasm/wasm_exec.js';
import wasmUrl from '../wasm/opf.wasm?url';

interface GoRuntime {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}

declare global {
  // eslint-disable-next-line no-var
  var Go: { new (): GoRuntime };
  // eslint-disable-next-line no-var
  var opfGenerators: Record<string, (json: string) => string> | undefined;
}

// The single-file build inlines the module as a data: URL; decode it
// rather than fetch it, which a host's policy may not allow.
async function wasmBytes(): Promise<BufferSource> {
  if (wasmUrl.startsWith('data:')) {
    const bin = atob(wasmUrl.slice(wasmUrl.indexOf(',') + 1));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  return (await fetch(wasmUrl)).arrayBuffer();
}

let ready: Promise<void> | null = null;

function load(): Promise<void> {
  ready ??= (async () => {
    const go = new globalThis.Go();
    const { instance } = await WebAssembly.instantiate(await wasmBytes(), go.importObject);
    void go.run(instance); // runs until the page goes away
    for (let i = 0; !globalThis.opfGenerators && i < 100; i++) await new Promise((r) => setTimeout(r, 10));
    if (!globalThis.opfGenerators) throw new Error('the generators didn’t start');
  })();
  return ready;
}

export class GeneratorError extends Error {}

/** Calls one of the Go functions: JSON in, {ok} or {error} out. */
export async function call<T>(name: string, request: unknown): Promise<T> {
  await load();
  const fn = globalThis.opfGenerators![name];
  if (!fn) throw new GeneratorError(`no generator function ${name}`);
  const res = JSON.parse(fn(JSON.stringify(request))) as { ok?: T; error?: string };
  if (res.error !== undefined) throw new GeneratorError(res.error);
  return res.ok as T;
}
