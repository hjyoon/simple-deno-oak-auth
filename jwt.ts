import {
  getNumericDate,
  Header,
  Payload,
} from "https://deno.land/x/djwt@v2.7/mod.ts";

export const key: CryptoKey = await crypto.subtle.generateKey(
  { name: "HMAC", hash: "SHA-512" },
  true,
  ["sign", "verify"]
);

export const accessPayload: Payload = { exp: getNumericDate(60 * 1) };

export const refreshPayload: Payload = { exp: getNumericDate(60 * 60) };

export const header: Header = { alg: "HS512", typ: "JWT" };
