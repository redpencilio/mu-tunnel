// see https://github.com/mu-semtech/mu-javascript-template for more info
import { app, errorHandler, uuid, sparqlEscapeDateTime } from 'mu';
import { querySudo as query, updateSudo as update } from '@lblod/mu-auth-sudo';
import fs from 'fs';
import bodyParser from 'body-parser';
import * as pgp from 'openpgp';
import { Buffer } from 'buffer';
import * as http from "http";

// load config
const config = require('/config/config.json');

console.log(process.version);
console.log(config);

checkConfig();

// Enable compression
pgp.config.compressionLevel = process.env.PGP_COMPRESSION_LEVEL || 9;
pgp.config.preferredCompressionAlgorithm = pgp.enums.compression.zlib;

app.use(bodyParser.json({ type: "application/json" }));
app.use(bodyParser.text({ type: "text/plain" }));
app.use(bodyParser.raw({ type: "application/octet-stream" }));

// Endpoint for INBOUND messages, e.g. another tunnel service relaying a remote message
app.post('/secure', async (req, res) => {
  // Read the PGP message
  let message;
  try {
    switch (req.get('Content-Type')) {
      case "text/plain":
        message = await pgp.readMessage({ armoredMessage: req.body });
        break;
      case "application/octet-stream":
        message = await pgp.readMessage({ binaryMessage: req.body });
        break;
      default:
        throw `Received message with Content-Type ${req.get('Content-Type')}`;
    }
  }
  catch (err) {
    console.error("Bad PGP message.", err);
    res.status(400).send("Bad PGP message.");
    throw err;
  }

  // Decrypt the PGP message
  const { data: payloadstring, signatures } = await pgp.decrypt({
    message,
    verificationKeys: config.peer.key,
    decryptionKeys: config.self.key
  });

  // Verify the signature
  let sigKeyID;
  try {
    if (await signatures[0].verified) {
      sigKeyID = signatures[0].keyID;
    }
    else {
      throw `Could not verify signature by key ${signatures[0].keyID}`;
    }
  }
  catch (err) {
    console.error("Unable to verify signature.", err);
    res.status(401).send("Cannot verify key.");
    throw err;
  }

  // Connect the verified signature to a known peer
  const peer = config.peer;
  //const peer = config.peers.find(peer => signatures[0].keyID.equals(peer.key.getKeyID()));

  // Parse the decrypted message
  let payload;
  try {
    payload = JSON.parse(payloadstring);
  }
  catch (err) {
    console.error(`Could not parse decrypted payload: ${payloadstring}`, err);
    res.status(400).send("Unparseable plaintext.");
    throw err;
  }

  if (process.env.TUNNEL_LOG_INBOUND) {
    console.log(`Received message from ${peer.identity}: ${JSON.stringify(payload, undefined, 2)}`);
  }
  else {
    console.log(`Received message from ${peer.identity}.`);
  }

  // Check if the request URL matches any of the allowed path prefixes.
  if (!peer.allowed || peer.allowed.find(prefix => payload.url.startsWith(prefix)) === undefined) {
    if (peer.allowed && peer.allowed.length > 0) {
      console.error(`Received request for path ${payload.url} not in allowlist ${peer.allowed.toString()} of ${peer.identity}.`);
    }
    else {
      console.error(`Received request for path ${payload.url} from peer ${peer.identity} with empty allowlist.`);
    }
    res.status(403).send("Path not allowed");
    throw err;
  }

  // Set some headers
  let headers = payload.headers || {};
  headers['mu-call-id'] = uuid();
  if (payload.headers && payload.headers['mu-call-id']) {
    headers['mu-call-id-trail'] = [...(payload.headers['mu-call-id-trail'] || []), payload.headers['mu-call-id']];
  }
  headers['mu-tunnel-identity'] = peer.identity;

  // Forward the request and construct a response object.
  let resobj;
  try {
    let body = payload.body ? Buffer.from(payload.body, 'base64') : undefined;
    let forwardres = await httpPromise(payload.url, headers, payload.method, body);
    resobj = await new Promise((resolve, reject) => {
      let chunks = [];
      forwardres.on('data', chunk => chunks.push(chunk));
      forwardres.on('end', () => resolve({
        headers: forwardres.headers,
        status: forwardres.statusCode,
        body: Buffer.concat(chunks).toString('base64')}));
      forwardres.on('error', err => reject(err));
    });
  }
  catch (err) {
    console.error(`Error while forwarding request: ${err}`);
    res.status(502);
    throw err;
  }

  // Encrypt the response object
  const encrypted = await pgp.encrypt({
    message: await pgp.createMessage({ text: JSON.stringify(resobj) }),
    encryptionKeys: peer.key,
    signingKeys: config.self.key,
    format: 'armored'
  });

  // Send the response
  res.set('Content-Type', 'text/plain')
     .status(200)
     .send(encrypted);
  console.log(`Succesfully responded to message from ${peer.identity}.`);
});

// Endpoint for OUTBOUND messages, e.g. internal services that want to contact another stack.
app.post('/out', async (req, res) => {
  if (process.env.TUNNEL_LOG_OUTBOUND) {
    console.log(`Received message: ${JSON.stringify(req.body, undefined, 2)}`);
  }
  else {
    console.log(`Received message.`);
  }

  const peer = config.peer;
  //TODO checking for an address can be done beforehand since there is only one peer and there should always be an address
  if (!peer.address) {
    console.error(`No address for peer ${peer.identity}.`);
    res.status(400).send("No peer address.");
    throw err;
  }

  // Encrypt the message
  let encrypted;
  try {
    encrypted = await pgp.encrypt({
      message: await pgp.createMessage({ text: JSON.stringify(req.body) }),
      encryptionKeys: peer.key,
      signingKeys: config.self.key,
      format: 'armored'
    });
  }
  catch (err) {
    console.error(`Could not encrypt message: ${err}`);
    res.status(500).send("Failed to encrypt.");
    throw err;
  }

  // Send the encrypted message and read the response
  let message;
  try {
    let peerres = await httpPromise(peer.address, { 'Content-Type' : 'text/plain' }, 'POST', encrypted);
    message = await new Promise((resolve, reject) => {
      let chunks = [];
      peerres.on('data', chunk => chunks.push(chunk));
      peerres.on('end', () => resolve(Buffer.concat(chunks).toString()));
      peerres.on('error', err => reject(err));
    });
  }
  catch (err) {
    console.error(`Error while forwarding request: ${err}`);
    res.status(502).send("Forwarding failed.");
    throw err;
  }

  // Decrypt the PGP response
  let payloadstring;
  try {
    ({ data: payloadstring } = await pgp.decrypt({
      message: await pgp.readMessage({ armoredMessage: message }),
      verificationKeys: peer.key, // We know the peer, so we know which key to expect.
      decryptionKeys: config.self.key,
      expectSigned: true
    }));
  }
  catch (err) {
    console.error(`Failed to decrypt response: ${err}`);
    res.status(502).send("Failed to decrypt.");
    throw err;
  }

  // Parse the response
  let payload;
  try {
    payload = JSON.parse(payloadstring);
  }
  catch (err) {
    console.error(`Failed to parse payload: ${err}`, payload);
    res.status(502).send("Unparseable payload.");
    throw err;
  }

  // Forward the response to the requester.
  for (let header in payload.headers) {
    res.set(header, payload.headers[header]);
  }
  res.status(payload.status)
     .send(Buffer.from(payload.body, 'base64'));
  console.log(`Succesfully handled request to ${peer.identity}.`);
});

// Wrap http.request in a promise
function httpPromise(addr, headers, method, body) {
  return new Promise((resolve, reject) => {
    let req = http.request(addr,
                           { headers: headers,
                             method: method },
                           forwardres => resolve(forwardres) )
    req.on('error', err => reject(err))
    if(body) {
      req.write(body)
    }
    req.end();
  });
}

async function loadKeys() {
  try {
    for (let peer of config.peers) {
      const key = await pgp.readKey({armoredKey: await readKeyFile(peer.file)});
      await checkKey(key, peer.identity); // Kind of hacky to only have a function that throws exceptions, but its the simplest
      peer.key = key;

      console.log(`Loaded peer public key ${key.getKeyID().toHex()} (${peer.identity}) from ${peer.file}.`);
    }

    const self = config.self;
    const key = await pgp.decryptKey({
      privateKey: await pgp.readPrivateKey({armoredKey: await readKeyFile(self.file)}),
      passphrase: config.self.passphrase
    });
    await checkKey(key, self.identity);
    config.self.key = key;

    console.log(`Loaded self secret key ${key.getKeyID().toHex()} (${self.identity}) from ${self.file}.`);
  }
  catch (err) {
    console.error("Exception during key loading, aborting.", err)
  }
}

// Check expiry and that the key identity matches.
async function checkKey(key, identity) {
  const expire = await key.getExpirationTime();
  const keyid = key.getKeyID().toHex();
  const user = (await key.getPrimaryUser()).user.userID.userID;
  if (Date() > expire) {
    throw `Key ${keyid} (${user}) expired on ${expire}.`;
  } else if (expire === Infinity) {
    console.warn(`Key ${keyid} (${user}) has no expiry.`);
  }

  if (user !== identity) {
    throw `Key ${keyid} (${user}) does not match identity ${identity}.`;
  }
}

async function readKeyFile(file) {
  return new Promise((resolve, reject) => {
    fs.readFile(`/config/keys/${file}`, { encoding: "utf-8" }, (err, data) => {
      if (err)
        reject(err);
      else
        resolve(data);
    });
}

function checkConfig() {
  if (!config || !config.self || !config.peer || !config.peer.address) {
    console.log("Config incomplete, sleeping for 60 seconds to allow script discovery.");
    setTimeout(async () => await loadKeys(), 60000)
  }
  else {
    // Load PGP keys
    await loadKeys();
  }
}

