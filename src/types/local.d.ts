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

export interface Opaque extends OpaqueSync {
  /**
   * Sign up as a new user
   */
  clientRegister: (password: string, user_id: string, op_id?: string) => Promise<boolean>;

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

type NewClientAuthOut = ClientState & {
  register: IOMap["register"],
  client_auth_data: IOMap["client_auth_data"]
}

type ClientSecretIn = ClientState & {
  server_auth_data: IOMap["server_auth_data"]
}

type ClientSecretOut = {
  token: string,
  client_auth_result: IOMap["client_auth_result"]
}

type ServerSecretIn = {
  pepper: Pepper,
  client_auth_data: IOMap["client_auth_data"]
}

type ServerSecretOut = {
  token: string,
  Au: Uint8Array,
  server_auth_data: IOMap["server_auth_data"]
}

export interface UserRecord {
  id: string;
  pepper: Pepper;
}
