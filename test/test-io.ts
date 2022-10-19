import type { IO, IOValue } from "../src/types/io"

/*
 *  Client-Server Communications
 */
const listeners: Record<string, (val: IOValue) => void> = {};
const mailbox: Record<string, IOValue> = {};
const dummy_socket = (computation_id: string): IO => ({
  get: (op_id, tag) => {
    return new Promise(function (resolve) {
      const _tag = computation_id + ':' + op_id + ':' + tag;
      const mail = mailbox[_tag];
      if (!mail) {
        // console.log('io.get', _tag, 'not ready');
        listeners[_tag] = resolve;
      } else {
        // console.log('io.get', _tag, mail);
        resolve(mail);
        delete mailbox[_tag];
      }
    });
  },
  give: (op_id, tag, msg) => {
    const _tag = computation_id + ':' + op_id + ':' + tag;
    // console.log('io.give', _tag, msg);
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
