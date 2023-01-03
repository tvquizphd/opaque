import type { IO } from "./types/io";
import type { Opaque } from "./types/local";
import type { NewClientAuthOut } from "./types/local";
import type { ClientSecretIn } from "./types/local";
import type { ClientSecretOut } from "./types/local";
import type { ServerSecretIn } from "./types/local";
import type { ServerSecretOut } from "./types/local";
import type { ServerFinal as SF } from "./types/local";
import type { OpaqueSync } from "./types/local";
import OPRF from "oprf";
import { opaqueFactory } from "./lib/opaque";
import { opaqueSyncFactory } from "./lib/opaque";
export type { Pepper } from "./types/io";
export type NewClientOut = NewClientAuthOut;
export type ClientIn = ClientSecretIn;
export type ClientOut = ClientSecretOut;
export type ServerIn = ServerSecretIn;
export type ServerOut = ServerSecretOut;
export type ServerFinal = SF;
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
