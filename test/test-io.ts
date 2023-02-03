import type { Io } from "../src/index"

type Mailbox = Record<string, unknown>
type Listeners = Record<string, (v: unknown) => void>
/*
 *  Client-Server Communications
 */
const listeners: Listeners = {};
const mailbox: Mailbox = {};
const dummy_socket = (computation_id: string): Io => ({
  get: (op_id, tag) => {
    return new Promise(function (resolve) {
      const _tag = computation_id + ':' + op_id + ':' + tag;
      const mail = mailbox[_tag]
      if (!mail) {
        // console.debug('io.get', _tag, 'not ready');
        listeners[_tag] = resolve
      } else {
        // console.debug('io.get', _tag, mail);
        resolve(mail);
        delete mailbox[_tag];
      }
    });
  },
  give: async (op_id, tag, msg) => {
    const _tag = computation_id + ':' + op_id + ':' + tag;
    // console.debug('io.give', _tag, msg);
    const listener = listeners[_tag];
    if (!listener) {
      mailbox[_tag] = msg;
    } else {
      listener(msg);
      delete listeners[_tag];
    }
  },
});

export = dummy_socket('example');
