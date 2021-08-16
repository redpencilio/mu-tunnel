// see https://github.com/mu-semtech/mu-javascript-template for more info
import { app, errorHandler, uuid, sparqlEscapeDateTime } from 'mu';
import { querySudo as query, updateSudo as update } from '@lblod/mu-auth-sudo';
import fs from 'fs-extra';
import bodyParser from 'body-parser';
import * as pgp from 'openpgp';
import { Buffer } from 'buffer';
const http = require('http');

// load config
const config = require('/config/config.js');

console.log(process.version);
console.log(config);

loadKeys();

app.use( bodyParser.json( { type: function(req) { return /^application\/json/.test( req.get('content-type') ); } } ) );

app.post('/secure', (req, res) => {
  // TODO: ensure HTTPS is used

  // Read the PGP message
  let message;
  try {
    if(req.get('Content-Type') === "text/plain") {
      message = await pgp.readMessage({armoredMessage: req.body});
    } else if(req.get('Content-Type') === "application/octet-stream") {
      message = await pgp.readMessage({binaryMessage: req.body});
    } else {
      throw `Received message with Content-Type ${req.get('Content-Type')}`;
    }
  } catch(err) {
    res.status(400).send("Bad PGP message.");
    console.error("Bad PGP message.");
    console.error(err);
    return;
  }

  // Decrypt the PGP message
  const {data: payloadstring, signatures} = await pgp.decrypt({
    message,
    verificationKeys: config.peers.map(peer => peer.key),
    decryptionKeys: config.self.key
  });

  // Verify the signature
  let sigKeyID;
  try {
    if(await signatures[0].verified) {
      sigKeyID = signatures[0].keyID;
    } else {
      throw `Could not verify signature by key ${signatures[0].keyID}`;
    }
  } catch(err) {
    console.error("Unable to verify signature.");
    console.error(err);
    res.status(401).send("Cannot verify key.");
    return;
  }

  // Connect the verified signature to a known peer
  const peer = config.peers.find(peer => signatures[0].keyID.equals(peer.key.getKeyID()));

  // Parse the decrypted message
  let payload;
  try {
    payload = JSON.parse(payloadstring);
  } catch(err) {
    console.error(`Could not parse decrypted payload:
  ${payloadstring}`);
    console.error(err);
    res.status(400).send("Unparseable plaintext.");
    return;
  }

  if(process.env.TUNNEL_LOG_INBOUND) {
    console.log(`Received message from ${peer.identity}:
${JSON.stringify(payload, undefined, 2)}`);
  } else {
    console.log(`Received message from ${peer.identity}.`);
  }

  // TODO: ACCESS CONTROL

  // Set some headers
  let headers = payload.headers;
  headers['mu-call-id'] = uuid();
  headers['mu-call-id-trail'] = [...(payload.headers['mu-call-id-trail'] || []), payload.headers['mu-call-id']];
  headers['mu-tunnel-identity'] = peer.identity;

  // Forward the request and construct a response object.
  let resobj = await new Promise((resolve, reject) => {
    http.request(payload.url,
                 { headers: headers,
                   method: payload.method },
                 (forwardres) => resolve(forwardres) )
        .on('error', (err) => reject(err))
        .write(Buffer.from(payload.body, 'base64'))
        .end();})
      .then(forwardres =>
        new Promise( (resolve, reject) => {
          let chunks = [];
          forwardres.on('data', chunk => chunks.push(chunk));
          forwardres.on('end', () => resolve({
            headers: forwardres.headers,
            status: forwarders.statusCode,
            body: Buffer.concat(chunks).toString('base64')}));
          forwardres.on('error', err => reject(err));}))
      .catch(err => {
        console.error(`Error while forwarding request: ${err}`);
        res.status(502);
        throw err;
      });

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

app.post('/out', (req, res) => {
  if(process.env.TUNNEL_LOG_OUTBOUND) {
    console.log(`Received message:
${JSON.stringify(payload, undefined, 2)}`);
  } else {
    console.log(`Received message.`);
  }

  // Identify the peer, e.g. the public key and address we have to use.
  const peer = config.peers.find(p => p.identity === req.body.peer);
  if(!peer) {
    console.error(`Received request for unknown peer ${peer.identity}`);
    res.status(400).send("Unknown peer");
    return;
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
  } catch(err) {
    console.error(`Could not encrypt message: ${err}`);
    res.status(500).send("Failed to encrypt.");
    return;
  }

  // Send the encrypted message and read the response
  let message;
  try {
    let peerres = await new Promise((resolve, reject) => {
      http.request(peer.address,
                   { headers: { 'Content-Type' : 'text/plain' },
                     method: 'POST' },
                   (forwardres) => resolve(forwardres) )
          .on('error', (err) => reject(err))
          .write(encrypted)
          .end();})
    message = await new Promise((resolve, reject) => {
      let acc = "";
      peerres.on('data', chunk => acc.append(chunk));
      peerres.on('end', () => resolve(acc));
      peerres.on('error', err => reject(err));
    });
  } catch(err) {
    console.error(`Error while forwarding request ${err}`);
    res.status(502).send("Forwarding failed.");
    return;
  }

  // Decrypt the PGP response
  let payloadstring;
  try {
    const {data: payloadstring} = await pgp.decrypt({
      message,
      verificationKeys: peer.key, // We know the peer, so we know which key to expect.
      decryptionKeys: config.self.key,
      expectSigned: true
    });
  } catch(err) {
    console.error(`Failed to decrypt response: ${err}`);
    res.status(502).send("Failed to decrypt.");
    return;
  }

  // Parse the response
  try {
    let payload = JSON.parse(payloadstring);
  } catch(err) {
    console.error(`Failed to parse payload: ${err}`);
    console.error(payload);
    res.status(502).send("Unparseable payload.");
  }

  // Forward the response to the requester.
  Object.keys(payload.headers).forEach(h => res.set(h, payload.headers[h]));
  res.status(payload.status);
  res.send(Buffer.from(payload.body, 'base64'));
  console.log(`Succesfully handled request to ${peer.identity}`);
});

async function loadKeys() {
  try {
    for (let i = 0; i < config.peers.length; i++) {
      const peer = config.peers[i];
      const key = await pgp.readKey({armoredKey: await readKeyFile(peer.file)});
      await checkKey(key, peer.identity); // Kind of hacky to only have a function that throws exceptions, but its the simplest
      config.peers[i].key = key;

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
  } catch (err) {
    console.error("Exception during key loading, aborting.")
    console.error(err);
    process.exit(1);
  }
}

// Check expiry and that the key identity matches.
async function checkKey(key, identity) {
  const expire = await key.getExpirationTime();
  const keyid = key.getKeyID().toHex();
  const user = (await key.getPrimaryUser()).user.userID.userID;
  if (Date() > expire) {
    throw `Key ${keyid} (${user}) expired on ${expire}.`;
  } else if(expire === Infinity) {
    console.warning(`Key ${keyid} (${user}) has no expiry.`);
  }

  if (user !== identity) {
    throw `Key ${keyid} (${user}) does not match identity ${identity}.`;
  }
}

function readKeyFile(file) {
  return fs.readFile(`/config/keys/${file}`, "utf-8");
}
