# Mu-tunnel

Service which allows tunneling of HTTP(S) requests between semantic.works stacks securely using the OpenPGP standard.

## Workings

This mu-tunnel takes requests for other services on its root endpoint and responds to all paths. The request is encapsulated and sent over the internal tunnel to be replayed in the other stack's configured endpoint. This is in contrast to the original tunnel, where you send a manually encapsulated request to a specific service via a POST request on the tunnel's `/out` path. The benefits of the new approach are:

* you don't need to know about the internals of the other stack, your request will be sent on the identifier/dispatcher, or other service specifically linked to this tunnel in the config of the other channel;
* you don't need to manually encapsulate a request, which means you can smoothly transition from accessing a remote service directly to using a tunnel by just changing the hostname of your request.

## API

Send your request with any path, parameters, headers and method to the root of the tunnel service.

## Features

This mu-tunnel (as forked from the original mu-tunnel) is more specified for mu.semte.ch stacks. This means we can rely on core assumptions. An overview of the assumptions and mechanisms behind this mu-tunnel:

*	The presence of an identifier or dispatcher (or another specific service) where all trafic will be routed to on both ends of the tunnel
*	The tunnel is symmetric: there can be communication in both directions
*	There are only 2 endpoints on this tunnel  
	For communicating to multiple stacks, use multiple tunnels
*	No more encapsulation of requests, this tunnel acts more like a HTTP-proxy for the identifier/dispatcher than a forwarder of messages

## Config

### Folder structure of config

The folder and file structure for the configuration of this tunnel should look like this:

```
├── config.json
├── cert
│   ├── cert.pem
│   └── key.pem
└── keys
    ├── producer-pub.asc
    └── producer-priv.asc
```
  
The `config.json` file contains the configuration. The `cert` folder contains keys and certificates for enabling HTTPS, and the `keys` folder contains the OpenPGP keys for encryption.

In Docker, mount this folder under the `/config` path.

### `config.json` file

A configuration file contains the following objects and properties:

* `self`: an object containing information about this tunnels node
  * `identity`: the identity of this node and the private key used by this node
  * `keyfile`: the path to the file storing this node's private key. This is a relative path starting from `keys/`. This key should be passphrase-protected.
  * `passphrase`: the passphrase to decrypt this node's private key
  * `stackentry`: the root URL to the service that the tunnel will forward all requests to (usually the identifier/dispatcher)
  * `httpscertfile`: the certificate file path for HTTPS, relative to the `cert/` folder (OPTIONAL only if DISABLE_HTTPS is set to true)
  * `httpskeyfile`: the key file path for HTTPS, relative to the `cert/` folder (OPTIONAL only if DISABLE_HTTPS is set to true)
* `peer`: all information about the other peer in this tunnel (only *one* other peer)
  * `identity`: the identity of that peer and its public key
  * `keyfile`: the file storing that peer's public key (same relative path starting from `keys/`)
  * `address`: the external endpoint where this peer can be reached to forward requests

A sample configuration looks like this:

```javascript
{
  "self": {
    "identity":      "producer@redpencil.io",
    "keyfile":       "producer-priv.asc",
    "passphrase":    "access",
    "stackentry":    "http://servicea/",
    "httpscertfile": "cert.pem",
    "httpskeyfile":  "key.pem"
  },
  "peer": {
    "identity": "consumer@redpencil.io",
    "keyfile":  "consumer-pub.asc",
    "address":  "https://tunnelb/secure"
  }
}
```

## Environment variables

The following environment variables can be used:

* `TUNNEL_LOG_INBOUND`: enables some logging about incoming messages to this tunnel (default: false)
* `TUNNEL_LOG_OUTBOUND`: enables some logging about outgoing messages to this tunnel (default: false)
* `DISABLE_HTTPS`: set to true if you do not want HTTPS being used, but HTTP (default: false)
* `PGP_COMPRESSION_LEVEL`: set the compression level for the PGP encryption (0 - 9, default: 9)

The following environment variable is a bit hacky:

* `NODE_TLS_REJECT_UNAUTHORIZED`: set to `'0'` if you don't want self signed HTTPS certificates being rejected. This is purely Node.js related. Keep in mind you should not use self signed certificates in production!

## HTTPS

It is strongly advised to run the tunnel's communication over HTTPS. Without HTTPS, messages can easily be intercepted and replayed at a later date, due to PGPs one-pass nature. To enable HTTPS, the following steps could be taken.

To create a self-singed HTTPS certificate and keyfile, execute the following commands on a shell and move the `key.pem` and `cert.pem` files into the `cert` folder and include their names in the config file. It is strongly discouraged to use self signed certificates in production! Create and register certificate and key files with a Certificate Authority instead.

```
openssl genrsa -out key.pem
openssl req -new -key key.pem -out csr.pem
openssl x509 -req -days 9999 -in csr.pem -signkey key.pem -out cert.pem
rm csr.pem
```
(Source: [How to create an https server?](https://nodejs.org/en/knowledge/HTTP/servers/how-to-create-a-HTTPS-server/))

**The rest of this file is taken from the original mu-tunnel.**

## Scripts

This service includes [mu-cli](https://github.com/mu-semtech/mu-cli) scripts for key and configuration management:
* `gen-privkey`: Generate a new elliptic curve GPG key for use with mu-tunnel
* `gen-pubkey`: Convert a private GPG key file into a public GPG key file.
* `config-self`: Configure this tunnel service by changing the settings of the key.
* `config-peer`: Configure the peers this service connects to.

## Keys [for OpenPGP encryption used in the tunnel]

RSA and other algorithms over integer fields can be quite slow, as they require very large keys. Elliptic curves offer similar security with smaller key sizes (256 bits instead of 4096 bits) and are thus much faster.

Therefore it is recommended to use elliptic curve keys with this service. Modern versions of `gpg` support elliptic curves, but the `--expert` flag must be passed to generate these keys.

Curve25519 is a widely used elliptic curve which is also [https://safecurves.cr.yp.to/rigid.html](rigid), unlike the NIST curves. It is thus a good choice.

The following are instructions to manually generate keys. However, the included mu-cli scripts can also be used for this (and should be easier to use).

To generate a new GPG key:

```
gpg --expert --full-generate-key
```

Follow the instructions and do not use a **(sign only)** or **(set your own capabilities)** key. Elliptic curves may be selected by choosing **ECC and ECC**.

To export a private key to a file:

```
gpg --export-secret-keys --armor privkey@example.org > privatekey.asc
```

To export a public key to a file:

```
gpg --export --armor pubkey@example.org > publickey.asc
```

