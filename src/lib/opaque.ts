import type { IO, IOData } from "../types/io";
import type { Opaque } from "../types/local";
import type * as Sodium from "libsodium-wrappers-sumo";
import type OPRF from "oprf";
import utilFactory from "./util";

export = (io: IO, sodium: typeof Sodium, oprf: OPRF): Opaque => {
  const util = utilFactory(sodium, oprf);

  // Sign up as a new user
  const clientRegister: Opaque["clientRegister"] = async (password, user_id, op_id) => {
    op_id = op_id + ":pake_init";
    const give = (v: IOData) => {
      if ("register" in v) io.give(op_id, "register", v);
    }
    const get_registered = async () => {
      const k = "registered";
      return (await io.get(op_id, k))[k];
    }
    const pw = util.oprfKdf(password);
    const register = {sid: user_id, pw };
    give({ register });

    return await get_registered();
  };

  // Register a new user for the first time
  const serverRegister: Opaque["serverRegister"] = async (t, op_id) => {
    op_id = op_id + ":pake_init";
    const give = (v: IOData) => {
      if ("registered" in v) io.give(op_id, "registered", v);
    }
    const get_register = async () => {
      const k = "register";
      return (await io.get(op_id, k))[k];
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
    const give = (v: IOData) => {
      if ("client_authenticated" in v) io.give(op_id, "client_authenticated", v);
      else if ("client_auth_data" in v) io.give(op_id, "client_auth_data", v);
      else if ("client_auth_result" in v) io.give(op_id, "client_auth_result", v);
    }
    const get_authenticated = async () => {
      const k = "authenticated";
      return (await io.get(op_id, k))[k];
    }
    const get_server_auth_data = async () => {
      const k = "server_auth_data";
      return (await io.get(op_id, k))[k];
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
    const give = (v: IOData) => {
      if ("authenticated" in v) io.give(op_id, "authenticated", v);
      else if ("server_auth_data" in v) io.give(op_id, "server_auth_data", v);
    }
    const get_client_auth_data = async () => {
      const k = "client_auth_data";
      return (await io.get(op_id, k))[k];
    }
    const get_client_auth_result = async () => {
      const k = "client_auth_result";
      return (await io.get(op_id, k))[k];
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
