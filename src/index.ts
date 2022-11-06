import type { IO } from "./types/io";
import type { Opaque } from "./types/local";
import type { OpaqueSync } from "./types/local";
import OPRF from "oprf";
import { opaqueFactory } from "./lib/opaque";
import { opaqueSyncFactory } from "./lib/opaque";
export type { Pepper } from "./types/io";
export type Ops = OpaqueSync;
export type Op = Opaque;
export type Io = IO;

const OP = async (io: IO): Promise<Opaque> => {
  const oprf = new OPRF();
  const opaque = opaqueFactory(io, oprf.sodium, oprf);

  await oprf.ready;
  return opaque;
};

const OPS = async (): Promise<OpaqueSync> => {
  const oprf = new OPRF();
  const opaque = opaqueSyncFactory(oprf.sodium, oprf);

  await oprf.ready;
  return opaque;
};

export {
  OP, OPS
};
