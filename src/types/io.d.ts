type O<K extends string, V> = Record<K, V>
type ByteArrayLeaf<I extends string> = O<I, Uint8Array>
type ByteArrayNode<I extends string, J extends string> = O<I, ByteArrayLeaf<J>>
type ByteArrayRoot<I extends string, J extends string, K extends string> = O<I, ByteArrayNode<J, K>>

type KeyC = "pu" | "Pu" | "Ps";
type ValC = "mac_tag" | "body";
type C = ByteArrayRoot<"c", KeyC, ValC>
type KeyPepper = "ks" | "ps" | "Ps" | "Pu"
export type Pepper = ByteArrayLeaf<KeyPepper> & C
export type Ciphertext = ByteArrayLeaf<ValC>

export type Mailbox = Record<string, unknown>
export type Listeners = Record<string, (v: unknown) => void>
export type IOMap = {
  registered: boolean;
  authenticated: boolean;
  client_authenticated: boolean;
  register: ByteArrayLeaf<"pw"> & Record<"sid", string>;
  server_auth_data: ByteArrayLeaf<"beta" | "Xs" | "As"> & C;
  client_auth_data: ByteArrayLeaf<"alpha" | "Xu">;
  client_auth_result: ByteArrayLeaf<"Au">;
}
export type IOData = Partial<IOMap>;
export type OpId = string | undefined;
export interface IO {
  give: (op_id: OpId, k: string, v: unknown) => void;
  get: (op_id: OpId, k: string) => Promise<unknown>;
}
