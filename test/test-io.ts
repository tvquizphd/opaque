import type { TagInts, TagBool, TagStr, TagC } from "../src/types/io"
import type { OpId, Tag, IOValue } from "../src/types/io"
import type { C } from "../src/types/local";

/*
 *  Client-Server Communications
 */
const listeners: Record<string, (val: IOValue) => void> = {};
const mailbox: Record<string, IOValue> = {};
const dummy_socket = (computation_id: string) => {
  function get(op_id: OpId, tag: TagInts): Promise<Uint8Array>;
  function get(op_id: OpId, tag: TagBool): Promise<boolean>;
  function get(op_id: OpId, tag: TagStr): Promise<string>;
  function get(op_id: OpId, tag: TagC): Promise<C>;
  function get(op_id: OpId, tag: Tag): Promise<IOValue> {
    return new Promise(function (resolve) {
      const _tag = computation_id + ':' + op_id + ':' + tag;
      const mail = mailbox[_tag] as IOData[typeof tag] | undefined; // TODO: Factor these assertions out
      if (!mail) {
        // console.debug('io.get', _tag, 'not ready');
        listeners[_tag] = resolve as (val: IOValue) => void; // TODO: Factor these assertions out
      } else {
        // console.debug('io.get', _tag, mail);
        resolve(mail);
        delete mailbox[_tag];
      }
    });
  }

  function give (op_id: OpId, tag: TagInts, msg: Uint8Array): void;
  function give (op_id: OpId, tag: TagBool, msg: boolean): void;
  function give (op_id: OpId, tag: TagStr, msg: string): void;
  function give (op_id: OpId, tag: TagC, msg: C): void;
  function give (op_id: OpId, tag: Tag, msg: IOValue): void {
    const _tag = computation_id + ':' + op_id + ':' + tag;
    // console.debug('io.give', _tag, msg);
    const listener = listeners[_tag];
    if (!listener) {
      mailbox[_tag] = msg;
    } else {
      listener(msg);
      delete listeners[_tag];
    }
  }
  return { get, give };
}
export = dummy_socket('example');
