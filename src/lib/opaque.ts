import type { IO, IOMap, OpId } from "../types/io";
import type { Opaque, OpaqueSync, PromiseStep, HasToken } from "../types/local";
import type { ClientFirst, ClientFinal, ClientStage } from "../types/local";
import type { ServerFirst, ServerFinal, ServerStage } from "../types/local";
import type * as Sodium from "libsodium-wrappers-sumo";
import type OPRF from "oprf";
import utilFactory from "./util";

type Tag = keyof IOMap;
type Pair = [Tag, Partial<IOMap>];
type ForKey<T extends Tag> = Pick<IOMap, T>;
type KeyPair<T extends Tag> = [T, ForKey<T>];
type GetKey<T extends Tag> = Promise<ForKey<T>>;

const TAGS: Tag[] = [
  "register", "server_auth_data", "client_auth_data",
  "client_auth_result"
]

function isNumber(u: unknown): u is number {
  return typeof u === "number";
}

function isTag(s: string | undefined): s is Tag {
  return (TAGS as string[]).includes(s || "");
}
function isIOValue(v: unknown): v is Partial<IOMap> {
  if (typeof v !== 'object' || !v) {
    return false; 
  }
  const keys = Object.keys(v).map(s => `${s}`);
  return keys.length === 1 && keys.every(isTag);
} 

function is(k: Tag, p: Pair): p is KeyPair<typeof k> {
  return p[0] in p[1] && p[0] === k;
}

function isClientFirst(o: ClientStage): o is ClientFirst {
  const s = o as ClientFirst;
  return [s.user_id, s.password].every(v => typeof v === "string");
}

function isClientFinal(o: ClientStage): o is ClientFinal {
  const s = o as ClientFinal;
  const all_state = [s.r, s.mask, s.xu].every(v => {
    return v?.constructor === Uint8Array;
  });
  if (s.client_auth_data && all_state) {
    const {client_auth_data: cad } = s;
    const has_sid = typeof cad.sid === "string";
    return has_sid && [cad.pw, cad.alpha, cad.Xu].every(v => {
      return v?.constructor === Uint8Array;
    });
  }
  return false;
}

function isServerFirst(o: ServerStage): o is ServerFirst {
  const s = o as ServerFirst;
  if (s.pepper) {
    const { ks, ps, Ps, Pu, c } = s.pepper;
    if (c && c.pu && c.Pu && c.Ps) {
      const keys = [ 
        c.pu.mac_tag, c.Pu.mac_tag, c.Ps.mac_tag,
        c.pu.body, c.Pu.body, c.Ps.body
      ];
      return [ ...keys, ks, ps, Ps, Pu ].every(v => {
        return v.constructor === Uint8Array;
      });
    }
  }
  return false;
}

function isServerFinal(o: ServerStage): o is ServerFinal {
  const s = o as ServerFinal;
  if (s.Au && s.token) {
    const needs = [
      s.Au.constructor === Uint8Array,
      typeof s.token === "string"
    ];
    return needs.every(v => v);
  }
  return false;
}

const opaqueSyncFactory = (sodium: typeof Sodium, oprf: OPRF): OpaqueSync => {

  const util = utilFactory(sodium, oprf);

  const toNewClientAuth: Opaque["toNewClientAuth"] = (args) => {
    const { password, user_id: sid } = args;

    const pw = util.oprfKdf(password);
    const r = sodium.crypto_core_ristretto255_scalar_random();
    const xu = sodium.crypto_core_ristretto255_scalar_random();

    const _H1_x_ = util.oprfH1(pw);
    const H1_x = _H1_x_.point;
    const mask = _H1_x_.mask;
    const a = util.oprfRaise(H1_x, r);

    const Xu = sodium.crypto_scalarmult_ristretto255_base(xu);
    const client_auth_data = { alpha: a, Xu, sid, pw };

    return { client_auth_data, r, xu, mask };
  }

  const toClientSecret: Opaque["toClientSecret"] = (args, t) => {
    const { r, xu, mask, server_auth_data } = args;

    const { beta: b, c, Xs, As: __As } = server_auth_data;

    if (!sodium.crypto_core_ristretto255_is_valid_point(b)) {
      return 1;
    }

    const r_inv = sodium.crypto_core_ristretto255_scalar_invert(r);
    const rw = util.iteratedHash(util.oprfH(util.oprfRaise(b, r_inv), mask), t);
    const pu = util.sodiumAeadDecrypt(rw, c.pu);

    if (!sodium.crypto_core_ristretto255_is_valid_point(pu)) {
      return 2;
    }

    const Ps = util.sodiumAeadDecrypt(rw, c.Ps);
    const K = util.KE(pu, xu, Ps, Xs);
    const SK = util.oprfF(K, util.sodiumFromByte(0));
    const As = util.oprfF(K, util.sodiumFromByte(1));
    const Au = util.oprfF(K, util.sodiumFromByte(2));
    const token = sodium.to_hex(SK);

    // The comparable value of 0 means equality
    if (sodium.compare(As, __As) !== 0) {
      return 3;
    }

    const client_auth_result = { Au };
    return { token, client_auth_result };
  }


  const toServerPepper: Opaque["toServerPepper"] = ({ sid, pw }, t) => {
    const ks = sodium.crypto_core_ristretto255_scalar_random();
    const rw = util.iteratedHash(util.oprfF(ks, pw), t);
    const ps = sodium.crypto_core_ristretto255_scalar_random();
    const pu = sodium.crypto_core_ristretto255_scalar_random();
    const Ps = sodium.crypto_scalarmult_ristretto255_base(ps);
    const Pu = sodium.crypto_scalarmult_ristretto255_base(pu);
    const c = {
      pu: util.sodiumAeadEncrypt(rw, pu),
      Pu: util.sodiumAeadEncrypt(rw, Pu),
      Ps: util.sodiumAeadEncrypt(rw, Ps),
    };
    return { id: sid, pepper: { ks: ks, ps: ps, Ps: Ps, Pu: Pu, c: c } };
  }

  const toServerSecret: Opaque["toServerSecret"] = (args) => {
    const { pepper, client_auth_data } = args;
    const { alpha: a, Xu } = client_auth_data;
    if (!sodium.crypto_core_ristretto255_is_valid_point(a)) {
      return 1;
    }
    const xs = sodium.crypto_core_ristretto255_scalar_random();
    const b = util.oprfRaise(a, pepper.ks);
    const Xs = sodium.crypto_scalarmult_ristretto255_base(xs);

    const K = util.KE(pepper.ps, xs, pepper.Pu, Xu);
    const SK = util.oprfF(K, util.sodiumFromByte(0));
    const As = util.oprfF(K, util.sodiumFromByte(1));
    const Au = util.oprfF(K, util.sodiumFromByte(2));
    const token = sodium.to_hex(SK);

    const server_auth_data = { beta: b, Xs, c: pepper.c, As };
    return { server_auth_data, token, Au };
  }

  return {
    toNewClientAuth,
    toClientSecret,
    toServerPepper,
    toServerSecret
  }
}

const opaqueFactory = (io: IO, sodium: typeof Sodium, oprf: OPRF) => {
  const util = utilFactory(sodium, oprf);
  const ops = opaqueSyncFactory(sodium, oprf);
  const {
    toNewClientAuth,
    toClientSecret,
    toServerPepper,
    toServerSecret
  } = ops;

  function giver(op_id: OpId, v: unknown): Promise<void> {
    if (!isIOValue(v)) {
      const e = new Error('Missing tag');
      return Promise.reject(e);
    }
    const k = Object.keys(v)[0];
    if (isTag(k)) {
      const p: Pair = [k, v];
      for (const tag of TAGS) {
        if (is(tag, p)) {
          return io.give(op_id, tag, v);
        }
      }
    }
    const e = new Error('Invalid tag');
    return Promise.reject(e);
  }
  async function getter (op_id: OpId, k: Partial<Tag>): GetKey<typeof k>;
  async function getter (op_id: OpId, k: string): Promise<unknown> {
    const v = await io.get(op_id, k);
    if (isIOValue(v) && k in v && isTag(k)) {
      const p: Pair = [k, v];
      for (const tag of TAGS) {
        if (is(tag, p)) return v;
      }
    }
    throw new Error("Invalid value received!");
  }

  const logClientError = (i: number) => {
    const client_error = "client_authenticated_" + i + " false";
    console.debug(client_error + " user");
    return client_error;
  }

  const logServerError = (message: string) => {
    const error = "Authentication failed.  " + message;
    console.debug(error);
    return error;
  }

  // Sign up as a new user
  const clientRegister: Opaque["clientRegister"] = (password, user_id, op_id) => {
    op_id = op_id + ":pake_init";
    const pw = util.oprfKdf(password);
    const register = { sid: user_id, pw };
    return giver(op_id, { register });
  };

  // Register a new user for the first time
  const serverRegister: Opaque["serverRegister"] = async (t, op_id) => {
    op_id = op_id + ":pake_init";
    const get_register = async () => {
      const k = "register";
      return (await getter(op_id, k))[k];
    }
    const { sid, pw } = await get_register();
    return toServerPepper({ sid, pw }, t);
  };

  async function clientStep (stage: ClientFirst, t?: number, op_id?: string): Promise<ClientFinal>
  async function clientStep (stage: ClientFinal, t?: number, op_id?: string): Promise<HasToken>
  async function clientStep (stage: ClientStage, t?: number, op_id?: string): PromiseStep {
    op_id = op_id + ":pake";
    const give = (v: unknown) => giver(op_id, v);
    const get_server_auth_data = async () => {
      const k = "server_auth_data";
      return (await getter(op_id, k))[k];
    }
    if (isClientFirst(stage)) {
      const client_out = toNewClientAuth(stage); 
      const { client_auth_data } = client_out;
      await give({ client_auth_data });
      return client_out;
    }
    if (isClientFinal(stage)) {
      const { client_auth_data, mask, r, xu } = stage;
      const server_auth_data = await get_server_auth_data();
      const secret_args = { mask, r, xu, client_auth_data, server_auth_data };
      const client_result = toClientSecret(secret_args, t);
      if (isNumber(client_result)) {
        throw new Error(logClientError(client_result));
      }
      const { token, client_auth_result } = client_result;
      await give({ client_auth_result });
      return { token };
    }
    throw new Error(logClientError(0));
  }

  async function serverStep(stage: ServerFirst, op_id?: string): Promise<ServerFinal>
  async function serverStep(stage: ServerFinal, op_id?: string): Promise<HasToken>
  async function serverStep(stage: ServerStage, op_id?: string): PromiseStep {
    op_id = op_id + ":pake";
    const give = (v: unknown) => giver(op_id, v);
    const get_client_auth_data = async () => {
      const k = "client_auth_data";
      return (await getter(op_id, k))[k];
    }
    const get_client_auth_result = async () => {
      const k = "client_auth_result";
      return (await getter(op_id, k))[k];
    }
    if (isServerFirst(stage)) {
      const { pepper } = stage;
      const client_auth_data = await get_client_auth_data();
      const server_result = toServerSecret({ pepper, client_auth_data });
      if (isNumber(server_result)) {
        throw new Error(logServerError("Invalid client auth data."));
      }
      const { server_auth_data, Au, token } = server_result;
      await give({ server_auth_data });
      return { Au, token };
    }
    if (isServerFinal(stage)) {
      const { Au } = await get_client_auth_result();
      // The comparable value of 0 means equality
      if (sodium.compare(stage.Au, Au) === 0) {
        return { token: stage.token };
      }
      throw new Error(logServerError("Wrong password for user"));
    }
    throw new Error(logServerError("Invalid server stage"));
  }

  // Try to log in
  const clientAuthenticate: Opaque["clientAuthenticate"] = async (password, user_id, t, op_id) => {
    const step = await clientStep({ password, user_id }, t, op_id);
    return (await clientStep(step, t, op_id)).token;
  };

  // Authenticate a user
  const serverAuthenticate: Opaque["serverAuthenticate"] = async (user_id, pepper, op_id) => {
    console.log('Authenticating ' + user_id);
    const step = await serverStep({ pepper }, op_id);
    return (await serverStep(step, op_id)).token;
  };

  return {
    clientStep,
    serverStep,
    clientRegister,
    serverRegister,
    clientAuthenticate,
    serverAuthenticate,
    toNewClientAuth,
    toClientSecret,
    toServerPepper,
    toServerSecret
  };
};


export {
  opaqueFactory,
  opaqueSyncFactory
};
