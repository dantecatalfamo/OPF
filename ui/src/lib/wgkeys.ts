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

/** The public key of a WireGuard private key (base64), worked out here:
 *  WebCrypto exports an X25519 private key's public half in its JWK. */
export async function publicKeyOf(privateKey: string): Promise<string> {
  const raw = Uint8Array.from(atob(privateKey.trim()), (c) => c.charCodeAt(0));
  if (raw.length !== 32) throw new Error('a WireGuard private key is 44 characters of base64');
  const pkcs8 = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20, ...raw]);
  const key = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, true, ['deriveBits']);
  const jwk = await crypto.subtle.exportKey('jwk', key);
  return btoa(atob((jwk.x ?? '').replace(/-/g, '+').replace(/_/g, '/')));
}

/** A device's key pair: the browser's, or else the firewall's. */
export async function deviceKeyPair(): Promise<KeyPair> {
  const k = await browserKeyPair();
  if (k) return k;
  if (offline) throw new Error('This browser can’t make WireGuard keys');
  return api.newDeviceKey();
}
