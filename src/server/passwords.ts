// Password hashes for Keelson's users (scrypt, with a salt per password), and
// the one-time passwords and setup code Keelson hands out. Hashing runs off the
// event loop, so guesses can't stall the server.

import { randomBytes, randomInt, scrypt, scryptSync, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

export const MIN_PASSWORD = 12;
export const MAX_PASSWORD = 256;

const KEY_LENGTH = 64;
const scryptAsync = promisify(scrypt) as (password: string, salt: Buffer, keylen: number) => Promise<Buffer>;

/** `scrypt$<salt>$<key>`, both base64url. The prefix leaves room for another scheme later. */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  return encode(salt, await scryptAsync(password, salt, KEY_LENGTH));
}

/** For seeding the mock server and tests, which start synchronously. */
export function hashPasswordSync(password: string): string {
  const salt = randomBytes(16);
  return encode(salt, scryptSync(password, salt, KEY_LENGTH));
}

const encode = (salt: Buffer, key: Buffer) => `scrypt$${salt.toString("base64url")}$${key.toString("base64url")}`;

/** A hash nobody's password matches, so an unknown username costs as much time as a wrong password. */
const DUMMY = hashPasswordSync(randomBytes(16).toString("hex"));

export async function verifyPassword(password: string, hash: string | null): Promise<boolean> {
  const [scheme, salt, key] = (hash ?? DUMMY).split("$");
  if (scheme !== "scrypt" || !salt || !key) return false;
  const expected = Buffer.from(key, "base64url");
  const actual = await scryptAsync(password, Buffer.from(salt, "base64url"), expected.length);
  return hash !== null && timingSafeEqual(actual, expected);
}

/** A password for someone to sign in with once and then replace: 20 characters, about 120 bits. */
export const oneTimePassword = () => randomBytes(15).toString("base64url");

/** Letters and digits that can't be misread for each other (no 0/O, 1/I/L). */
const CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";

/** The code that creating the first admin needs off this machine: XXXX-XXXX-XXXX, about 59 bits. */
export function setupCode(): string {
  const chars = Array.from({ length: 12 }, () => CODE_ALPHABET[randomInt(CODE_ALPHABET.length)]);
  return [0, 4, 8].map((i) => chars.slice(i, i + 4).join("")).join("-");
}

/** Compares a typed setup code with the real one, ignoring case, spaces and dashes, in constant time. */
export function sameCode(typed: string, code: string): boolean {
  const norm = (s: string) => Buffer.from(s.toUpperCase().replace(/[\s-]/g, ""));
  const a = norm(typed);
  const b = norm(code);
  return a.length === b.length && timingSafeEqual(a, b);
}
