import type { C } from "./local";

export interface IOData {
  sid: string;
  pw: Uint8Array;
  registered: boolean;
  authenticated: boolean;
  client_authenticated: boolean;
  alpha: Uint8Array;
  beta: Uint8Array;
  c: C;
  Xu: Uint8Array;
  Xs: Uint8Array;
  As: Uint8Array;
  Au: Uint8Array;
}

export type Tag = keyof IOData;
export type IOValue = IOData[Tag];

type OpId = string | undefined;

export interface IO {
  give: (op_id: OpId, k: string, v: unknown) => void;
  get: (op_id: OpId, k: string) => Promise<unknown>;
}
