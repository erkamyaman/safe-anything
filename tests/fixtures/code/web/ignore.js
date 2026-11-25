const a = crypto.createHash('md5').update(body); // safe-anything:ignore code.weak-hash

const b = eval(crypto.createHash('md5').update(x).digest('hex')); // safe-anything:ignore code.weak-hash

// safe-anything:ignore code.eval, code.weak-hash
const c = eval(crypto.createHash('md5').update(y).digest('hex'));
// safe-anything:ignore code.weak-hash
const d = eval(req.body.code);

const e = eval(req.body.code); // safe-anything:ignore

const f = eval(req.body.code); // safe-anything:ignore false positive, reviewed

const g = eval(crypto.createHash('md5').update(z).digest('hex')); // safe-anything:ignore code.eval, secret.aws_access_key

const h = eval(req.body.code); // safe-anything:ignore code.js is generated

const i = eval(req.body.code); // safe-anything:ignore code.weak-hash code.eval

const j = crypto.createHash('md5').update(pw); const password = "{{fake:password}}"; // safe-anything:ignore code.weak-hash

const k = eval(req.body.code); const password = "{{fake:password}}"; // safe-anything:ignore code.eval - unlike secret.hardcoded-password this is safe

const l = crypto.createHash('md5').update(pw); // safe-anything:ignore not code.eval

const m = crypto.createHash('md5').update(pw); /* safe-anything:ignore */ // see code.eval

const n = eval(crypto.createHash('md5').update(q).digest('hex')); /* safe-anything:ignore code.eval*/

const o = crypto.createHash('md5').update(pw); // safe-anything:ignore code.weak-hashh

const p = crypto.createHash('md5').update(pw); // uses safe-anything:ignore, code.eval is fine

const q = eval(req.body.code); /* safe-anything:ignore code.x*/

const r = crypto.createHash('md5').update(pw); // safe-anything:ignore code.weak-hash: checksum
