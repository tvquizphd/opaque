import type { IO } from "./types/io";
import type { Opaque } from "./types/local";
export type { Pepper } from "./types/io";
export declare type Op = Opaque;
export declare type Io = IO;
declare const OP: (io: IO) => Promise<Opaque>;
export { OP };
