// Stands in for wasmGen.ts outside the offline preview build (see
// vite.config.ts): the real UI asks the server, and never gets here.
export class GeneratorError extends Error {}

export async function call<T>(name: string, _request: unknown): Promise<T> {
  throw new GeneratorError(`${name}: the Go generators are only built into the offline preview`);
}
