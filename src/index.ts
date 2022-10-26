import type { IO } from "./types/io";
import type { Opaque } from "./types/local";
import OPRF from "oprf";
import opaqueFactory from "./lib/opaque";

export type { Pepper } from "./types/io";
export type Op = Opaque;
export type Io = IO;

const OP = async (io: IO): Promise<Opaque> => {
  // The original code passed in an instance of `libsodium-wrappers-sumo`
  // to this constructor, but `OPRF` doesn't take any constructor args.
  const oprf = new OPRF();
  const opaque = opaqueFactory(io, oprf.sodium, oprf);

  await oprf.ready;
  return opaque;
};

export { OP };
