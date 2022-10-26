type O<K, V> = Record<K, V>
type ByteArrayLeaf<I> = O<I, Uint8Array>
type ByteArrayNode<I, J> = O<I, ByteArrayLeaf<J>>
type ByteArrayRoot<I, J, K> = O<I, ByteArrayNode<J, K>>

type KeyC = "pu" | "Pu" | "Ps";
type ValC = "mac_tag" | "body";
type C = ByteArrayRoot<"c", KeyC, ValC>
type KeyPepper = "ks" | "ps" | "Ps" | "Pu"
export type Pepper = ByteArrayLeaf<KeyPepper> & C
export type Ciphertext = ByteArrayLeaf<ValC>

export interface ClientRegData {
  register: ByteArrayLeaf<"pw"> & {
    sid: string
  }
}
export interface ServerRegData {
  registered: boolean
}
export interface ServerAuthStatus {
  authenticated: boolean
}
export interface ServerAuthData {
  server_auth_data: ByteArrayLeaf<"beta" | "Xs" | "As"> & C
}
export interface ClientAuthStatus {
  client_authenticated: boolean
}
export interface ClientAuthData {
  client_auth_data: ByteArrayLeaf<"alpha" | "Xu">
}
export interface ClientAuthResult {
  client_auth_result: ByteArrayLeaf<"Au">
}
export interface Get {
  (op_id: OpId, k: "register"): Promise<ClientRegData>
  (op_id: OpId, k: "registered"): Promise<ServerRegData>
  (op_id: OpId, k: "authenticated"): Promise<ServerAuthStatus>
  (op_id: OpId, k: "server_auth_data"): Promise<ServerAuthData>
  (op_id: OpId, k: "client_authenticated"): Promise<ClientAuthStatus>
  (op_id: OpId, k: "client_auth_data"): Promise<ClientAuthData>
  (op_id: OpId, k: "client_auth_result"): Promise<ClientAuthResult>
}
export interface Give {
  (op_id: OpId, k: "register", v: ClientRegData): void;
  (op_id: OpId, k: "registered", v: ServerRegData): void;
  (op_id: OpId, k: "authenticated", v: ServerAuthStatus): void;
  (op_id: OpId, k: "server_auth_data", v: ServerAuthData): void;
  (op_id: OpId, k: "client_authenticated", v: ClientAuthStatus): void;
  (op_id: OpId, k: "client_auth_data", v: ClientAuthData): void;
  (op_id: OpId, k: "client_auth_result", v: ClientAuthResult): void;
}
export type IOData = (
  ClientRegData |  ServerRegData |
  ServerAuthStatus | ServerAuthData |
  ClientAuthStatus | ClientAuthData | ClientAuthResult
)
export interface IO {
  give: Give;
  get: Get;
}
