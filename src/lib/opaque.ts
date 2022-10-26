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
  // Sign up as a new user
  const clientRegister: Opaque["clientRegister"] = async (password, user_id, op_id) => {
    op_id = op_id + ":pake_init";
    const give = (v: unknown) => giver(op_id, v);
    const get_registered = async () => {
      const k = "registered";
      return (await getter(op_id, k))[k];
    }
    const pw = util.oprfKdf(password);
    const register = {sid: user_id, pw };
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

    const user_record = { id: sid, pepper: { ks: ks, ps: ps, Ps: Ps, Pu: Pu, c: c } };
    const registered = true;
    give({ registered });

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

    const r = sodium.crypto_core_ristretto255_scalar_random();
    const xu = sodium.crypto_core_ristretto255_scalar_random();

    const pw = util.oprfKdf(password);
    const _H1_x_ = util.oprfH1(pw);
    const H1_x = _H1_x_.point;
    const mask = _H1_x_.mask;
    const a = util.oprfRaise(H1_x, r);

    const Xu = sodium.crypto_scalarmult_ristretto255_base(xu);
    const client_auth_data = { alpha: a, Xu };
    give({ client_auth_data });

    const { beta: b, c, Xs, As: __As } = await get_server_auth_data();

    if (!sodium.crypto_core_ristretto255_is_valid_point(b)) {
      console.debug("client_authenticated_1 false " + user_id);
      give({client_authenticated: false });
      throw new Error("client_authenticated_1 false");
    }

    const r_inv = sodium.crypto_core_ristretto255_scalar_invert(r);
    const rw = util.iteratedHash(util.oprfH(util.oprfRaise(b, r_inv), mask), t);
    const pu = util.sodiumAeadDecrypt(rw, c.pu);

    if (!sodium.crypto_core_ristretto255_is_valid_point(pu)) {
      console.debug("client_authenticated_2 false " + user_id);
      give({client_authenticated: false });
      throw new Error("client_authenticated_2 false");
    }

    const Ps = util.sodiumAeadDecrypt(rw, c.Ps);
    const K = util.KE(pu, xu, Ps, Xs);
    const SK = util.oprfF(K, util.sodiumFromByte(0));
    const As = util.oprfF(K, util.sodiumFromByte(1));
    const Au = util.oprfF(K, util.sodiumFromByte(2));

    if (sodium.compare(As, __As) !== 0) {
      // The comparable value of 0 means As equals __As
      console.debug("client_authenticated_3 false " + user_id);
      give({client_authenticated: false });
      throw new Error("client_authenticated_3 false");
    }

    const client_auth_result = { Au };
    give({ client_auth_result });

    const success = await get_authenticated();
    if (success) {
      const token = sodium.to_hex(SK);
      return token;
    } else {
      console.debug("client_authenticated_4 false " + user_id);
      give({client_authenticated: false });
      throw new Error("client_authenticated_4 false");
    }
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

    const { alpha: a, Xu } = await get_client_auth_data();
    if (!sodium.crypto_core_ristretto255_is_valid_point(a)) {
      console.debug("Authentication failed.  Alpha is not a group element.");
      give({authenticated: false });
      throw new Error("Authentication failed.  Alpha is not a group element.");
    }
    const xs = sodium.crypto_core_ristretto255_scalar_random();
    const b = util.oprfRaise(a, pepper.ks);
    const Xs = sodium.crypto_scalarmult_ristretto255_base(xs);

    const K = util.KE(pepper.ps, xs, pepper.Pu, Xu);
    const SK = util.oprfF(K, util.sodiumFromByte(0));
    const As = util.oprfF(K, util.sodiumFromByte(1));
    const Au = util.oprfF(K, util.sodiumFromByte(2));

    const { c } = pepper;
    const server_auth_data = { beta: b, Xs, c, As };
    give({ server_auth_data });

    const { Au: __Au } = await get_client_auth_result();
    if (sodium.compare(Au, __Au) === 0) {
      // The comparable value of 0 means equality
      give({authenticated: true });
      const token = sodium.to_hex(SK);
      return token;
    } else {
      console.debug("Authentication failed.  Wrong password for " + user_id);
      give({authenticated: false });
      throw new Error("Authentication failed.  Wrong password for " + user_id);
    }
  };

  return {
    clientRegister,
    serverRegister,
    clientAuthenticate,
    serverAuthenticate,
  };
};
