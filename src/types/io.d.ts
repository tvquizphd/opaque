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
type register = ByteArrayLeaf<"pw"> & Record<"sid", string>
export type IOMap = {
  register: register;
  server_auth_data: ByteArrayLeaf<"beta" | "Xs" | "As"> & C;
  client_auth_data: ByteArrayLeaf<"alpha" | "Xu"> & register;
  client_auth_result: ByteArrayLeaf<"Au">;
}
export type IOData = Partial<IOMap>;
export type OpId = string | undefined;
export interface IO {
  give: (op_id: OpId, k: string, v: unknown) => Promise<void>;
  get: (op_id: OpId, k: string) => Promise<unknown>;
}
