import type { Ciphertext } from "../types/io";
import type OPRF from "oprf";
import type * as Sodium from "libsodium-wrappers-sumo";
declare const _default: (sodium: typeof Sodium, oprf: OPRF) => {
    oprfF: (k: Uint8Array, x: string | Uint8Array) => Uint8Array;
    oprfKdf: (pwd: string) => Uint8Array;
    oprfH: (x: Uint8Array, m: Uint8Array) => Uint8Array;
    oprfH1: (x: Uint8Array) => import("oprf/build/oprf.slim").IMaskedData;
    oprfRaise: (x: Uint8Array, y: Uint8Array) => Uint8Array;
    KE: (p: Uint8Array, x: Uint8Array, P: Uint8Array, X: Uint8Array) => Uint8Array;
    iteratedHash: (x: Uint8Array, t?: number | undefined) => Uint8Array;
    sodiumFromByte: (n: number) => Uint8Array;
    sodiumAeadEncrypt: (key: Uint8Array, plaintext: string | Uint8Array) => Ciphertext;
    sodiumAeadDecrypt: (key: Uint8Array, ciphertext: Ciphertext) => Uint8Array;
};
export default _default;
