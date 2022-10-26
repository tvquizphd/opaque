# opaque-low-io 

Typescript OPAQUE (OPRF asymmetric PAKE) with minimal client/server io.

This is a fork of [a typescript port][f1] of [@nthparty/opaque][f2].

## Protocol
Implementation of [this Internet Draft proposal](https://datatracker.ietf.org/doc/draft-krawczyk-cfrg-opaque).

## Installation

You may also install this module from [npm](https://www.npmjs.com/package/opaque-low-io).

```shell
npm install opaque-low-io
```

## Calling the API

The process generally works as follows:

```javascript
// Each party includes the 1-out-of-n module with IO:
const OT = require('opaque-low-io')(IO);

// Login credentials never reaches the server in plaintext
const user_id = 'newuser';
const password = 'correct horse battery staple';

// Sign up
OPAQUE.clientRegister(password, user_id).then(console.debug.bind(null, 'Registered:'));

// Log in for the first time and receive a session token
OPAQUE.clientAuthenticate(password, user_id).then(console.debug.bind(null, 'Shared secret:'));

// Register a new user
let user = OPAQUE.serverRegister();

// Handle a login attempt
OPAQUE.serverAuthenticate(user.id, user.pepper);

// Result:
'Registered: true'
'Login for newuser succeeded with: 4ccdf3b8cacf08273a085c952aaf3ee83633e6afcedf4f86c00497e862f43c78'
'Shared secret: 4ccdf3b8cacf08273a085c952aaf3ee83633e6afcedf4f86c00497e862f43c78'
```

[f1]: https://github.com/AverageHelper/opaque/tree/avg/typescript
[f2]: https://github.com/nthparty/opaque
