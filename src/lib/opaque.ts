import type { IO, IOMap, OpId } from "../types/io";
import type { Opaque } from "../types/local";
import type * as Sodium from "libsodium-wrappers-sumo";
import type OPRF from "oprf";
import utilFactory from "./util";

type Tag = keyof IOMap;
type Pair = [Tag, Partial<IOMap>];
type ForKey<T extends Tag> = Pick<IOMap, T>;
type KeyPair<T extends Tag> = [T, ForKey<T>];
type GetKey<T extends Tag> = Promise<ForKey<T>>;

const TAGS: Tag[] = [
  "registered", "authenticated", "client_authenticated",
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

export = (io: IO, sodium: typeof Sodium, oprf: OPRF): Opaque => {
  const util = utilFactory(sodium, oprf);

  function giver(op_id: OpId, v: unknown): void {
    if (!isIOValue(v)) {
      return;
    }
    const k = Object.keys(v)[0];
    if (!isTag(k)) {
      return;
    }
    const p: Pair = [k, v];
    for (const tag of TAGS) {
      if (is(tag, p)) {
        return io.give(op_id, tag, v);
      }
    }
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

  const logClientError = (i: number, user_id: string, op_id: string) => {
    const client_error = "client_authenticated_" + i + " false";
    console.debug(client_error + " " + user_id);
    giver(op_id, { client_authenticated: false });
    return client_error;
  }

  const logServerError = (message: string, op_id: string) => {
    const error = "Authentication failed.  " + message;
    console.debug(error);
    giver(op_id, {authenticated: false });
    return error;
  }

  const toNewClientAuth: Opaque["toNewClientAuth"] = (args) => {
    const { password, user_id } = args;

    const pw = util.oprfKdf(password);
    const register = { sid: user_id, pw };
    const r = sodium.crypto_core_ristretto255_scalar_random();
    const xu = sodium.crypto_core_ristretto255_scalar_random();

    const _H1_x_ = util.oprfH1(register.pw);
    const H1_x = _H1_x_.point;
    const mask = _H1_x_.mask;
    const a = util.oprfRaise(H1_x, r);

    const Xu = sodium.crypto_scalarmult_ristretto255_base(xu);
    const client_auth_data = { alpha: a, Xu };

    return { register, client_auth_data, r, xu, mask };
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

  // Sign up as a new user
  const clientRegister: Opaque["clientRegister"] = async (password, user_id, op_id) => {
    op_id = op_id + ":pake_init";
    const give = (v: unknown) => giver(op_id, v);
    const get_registered = async () => {
      const k = "registered";
      return (await getter(op_id, k))[k];
    }
    const pw = util.oprfKdf(password);
    const register = { sid: user_id, pw };
    give({ register });

    return await get_registered();
  };

  // Register a new user for the first time
  const serverRegister: Opaque["serverRegister"] = async (t, op_id) => {
    op_id = op_id + ":pake_init";
    const give = (v: unknown) => giver(op_id, v);
    const get_register = async () => {
      const k = "register";
      return (await getter(op_id, k))[k];
    }

    const { sid, pw } = await get_register();
    const user_record = toServerPepper({ sid, pw }, t);

    give({ registered: true });

    return user_record;
  };

  // Try to log in
  const clientAuthenticate: Opaque["clientAuthenticate"] = async (password, user_id, t, op_id) => {
    op_id = op_id + ":pake";
    const give = (v: unknown) => giver(op_id, v);
    const get_authenticated = async () => {
      const k = "authenticated";
      return (await getter(op_id, k))[k];
    }
    const get_server_auth_data = async () => {
      const k = "server_auth_data";
      return (await getter(op_id, k))[k];
    }

    const { client_auth_data, mask, r, xu } = toNewClientAuth({ password, user_id }); 

    give({ client_auth_data });

    const server_auth_data = await get_server_auth_data();

    const secret_args = { mask, r, xu, client_auth_data, server_auth_data };
    const client_result = toClientSecret(secret_args, t);

    if (isNumber(client_result)) {
      throw new Error(logClientError(client_result, user_id, op_id));
    }
    const { token, client_auth_result } = client_result;
    give({ client_auth_result });
    if (await get_authenticated()) {
      return token;
    }
    throw new Error(logClientError(4, user_id, op_id));
  };

  // Authenticate a user
  const serverAuthenticate: Opaque["serverAuthenticate"] = async (user_id, pepper, op_id) => {
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
    const client_auth_data = await get_client_auth_data();
    const server_result = toServerSecret({ pepper, client_auth_data });
    if (isNumber(server_result)) {
      throw new Error(logServerError("Alpha is not a group element.", op_id));
    }
    const { Au, server_auth_data, token } = server_result;
    give({ server_auth_data });

    const { Au: __Au } = await get_client_auth_result();

    // The comparable value of 0 means equality
    if (sodium.compare(Au, __Au) === 0) {
      give({ authenticated: true });
      return token;
    }
    throw new Error(logServerError("Wrong password for " + user_id, op_id));
  };

  return {
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
