import type { IOMap, Pepper } from "./io"

export interface OpaqueSync {
  /**
   * Client Authentication Initialization
   */
  toNewClientAuth: (a: NewClientAuthIn) => NewClientAuthOut;

  /**
   * Shared Secret on Client
   */
  toClientSecret: (a: ClientSecretIn, t?: number) => ClientSecretOut | number;

  /**
   * Server Registration Initialization
   */
  toServerPepper: (a: IOMap["register"], t?: number) => UserRecord;

  /**
   * Shared Secret on Server
   */
  toServerSecret: (a: ServerSecretIn) => ServerSecretOut | number;

}

export type PromiseStep = Promise<Record<string, unknown>>;
export type ClientFirst = { user_id: string, password: string };
export type ServerFinal = { token: string, Au: Uint8Array };
export type ServerFirst = { pepper: Pepper };
export type ClientFinal = NewClientAuthOut;
export type ClientStage = ClientFirst | ClientFinal;
export type ServerStage = ServerFirst | ServerFinal;
export type HasToken = { token: string };

export interface Opaque extends OpaqueSync {

  clientStep: {
    (stage: ClientFirst, t?: number, op_id?: string): Promise<ClientFinal>;
    (stage: ClientFinal, t?: number, op_id?: string): Promise<HasToken>;
  };
  serverStep: {
    (stage: ServerFirst, op_id?: string): Promise<ServerFinal>;
    (stage: ServerFinal, op_id?: string): Promise<HasToken>;
  };

  /**
   * Sign up as a new user
   */
  clientRegister: (password: string, user_id: string, op_id?: string) => Promise<void>;

  /**
   * Register a new user for the first time
   */
  serverRegister: (t?: number, op_id?: string) => Promise<UserRecord>;

  /**
   * Try to log in
   */
  clientAuthenticate: (
    password: string,
    user_id: string,
    t?: number,
    op_id?: string
  ) => Promise<string>;

  /**
   * Authenticate a user
   */
  serverAuthenticate: (user_id: string, pepper: Pepper, op_id?: string) => Promise<string>;
}

interface NewClientAuthIn {
  password: string;
  user_id: string;
}

type ClientState = {
  r: Uint8Array,
  xu: Uint8Array,
  mask: Uint8Array,
}

export type NewClientAuthOut = ClientState & {
  client_auth_data: IOMap["client_auth_data"]
}

export type ClientSecretIn = ClientState & {
  server_auth_data: IOMap["server_auth_data"]
}

export type ClientSecretOut = {
  token: string,
  client_auth_result: IOMap["client_auth_result"]
}

export type ServerSecretIn = {
  pepper: Pepper,
  client_auth_data: IOMap["client_auth_data"]
}

export type ServerSecretOut = ServerFinal & {
  server_auth_data: IOMap["server_auth_data"]
}

export interface UserRecord {
  id: string;
  pepper: Pepper;
}
