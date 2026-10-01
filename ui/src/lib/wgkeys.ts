// WireGuard key pairs for devices, made in the browser so a device's
// private key never reaches the firewall. WebCrypto's X25519 is
// WireGuard's curve; a browser without it asks the firewall, which
// makes a pair and keeps nothing.
import { api, offline } from './api';

export interface KeyPair {
  privateKey: string;
  publicKey: string;
}

const b64 = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(b)));

/** A key pair made here, or undefined if the browser can't. */
export async function browserKeyPair(): Promise<KeyPair | undefined> {
  try {
    const k = (await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])) as CryptoKeyPair;
    const pub = await crypto.subtle.exportKey('raw', k.publicKey);
    // PKCS #8 for X25519 is a 16-byte header and the 32-byte key.
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', k.privateKey));
    if (pkcs8.length !== 48 || new Uint8Array(pub).length !== 32) return undefined;
    return { privateKey: b64(pkcs8.slice(16)), publicKey: b64(pub) };
  } catch {
    return undefined;
  }
}

/** A device's key pair: the browser's, or else the firewall's. */
export async function deviceKeyPair(): Promise<KeyPair> {
  const k = await browserKeyPair();
  if (k) return k;
  if (offline) throw new Error('This browser can’t make WireGuard keys');
  return api.newDeviceKey();
}
