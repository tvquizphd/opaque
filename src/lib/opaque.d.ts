import type { IO } from "../types/io";
import type { Opaque } from "../types/local";
import type * as Sodium from "libsodium-wrappers-sumo";
import type OPRF from "oprf";
declare const _default: (io: IO, sodium: typeof Sodium, oprf: OPRF) => Opaque;
export default _default;
