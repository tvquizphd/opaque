import type { C } from "./local";

type IODataInts = {
  pw: Uint8Array,
  alpha: Uint8Array,
  beta: Uint8Array,
  Xu: Uint8Array,
  Xs: Uint8Array,
  As: Uint8Array,
  Au: Uint8Array
};
type IODataBool = {
  registered: boolean,
  authenticated: boolean,
  client_authenticated: boolean,
};
type IODataStr = {
  sid: string
};
type IODataC = {
  c: C
};
export type IOData = IODataInts & IODataBool & IODataStr & IODataC;

export type Tag = keyof IOData;
export type IOValue = IOData[Tag];
export type OpId = string | undefined;
export type TagInts = keyof IODataInts;
export type TagBool = keyof IODataBool;
export type TagStr = keyof IODataStr;
export type TagC = keyof IODataC;

export interface IO {
  get: <T extends Tag>(op_id: OpId, tag: T) => Promise<IOData[T]>;
  give: <T extends Tag>(op_id: OpId, tag: T, msg: IOData[T]) => void;
}
