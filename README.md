# mu-tunnel

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
*	No more encapsulation of requests, this tunnel acts more like a HTTP-proxy than a forwarder of messages

## Config

### Folder structure of config

The folder and file structure for the configuration of this tunnel should look like this:

```
├── config.json
└── keys
    ├── producer-pub.asc
    └── producer-priv.asc
```
  
The `config.json` file contains the configuration. The `keys` folder contains the OpenPGP keys for encryption.

In Docker, mount this folder under the `/config` path.

### `config.json` file

A configuration file contains the following objects and properties:

* `self`: an object containing information about this tunnels node
  * `identity`: the identity of this node and the private key used by this node
  * `keyfile`: the path to the file storing this node's private key. This is a relative path starting from `keys/`. This key should be passphrase-protected.
  * `passphrase`: the passphrase to decrypt this node's private key
  * `stackentry`: the root URL to the service that the tunnel will forward all requests to (possibly the identifier/dispatcher)
* `peer`: all information about the other peer in this tunnel (only *one* other peer)
  * `identity`: the identity of that peer and its public key
  * `keyfile`: the file storing that peer's public key (same relative path starting from `keys/`)
  * `address`: the external endpoint where this peer can be reached to forward requests (OPTIONAL, if left out, this tunnel is unidirectional and this current endpoint can only be used for receiving (and responding to) requests)

A sample configuration looks like this:

```javascript
{
  "self": {
    "identity":      "producer@redpencil.io",
    "keyfile":       "producer-priv.asc",
    "passphrase":    "access",
    "stackentry":    "http://servicea/"
  },
  "peer": {
    "identity": "consumer@redpencil.io",
    "keyfile":  "consumer-pub.asc",
    "address":  "https://identifier/tunnel/secure"
  }
}
```

## Environment variables

The following environment variables can be used:

* `TUNNEL_LOG_INBOUND`: enables some logging about incoming messages to this tunnel (default: false)
* `TUNNEL_LOG_OUTBOUND`: enables some logging about outgoing messages to this tunnel (default: false)
* `DISABLE_HTTPS`: set to true if you do not want HTTPS being used, but HTTP (default: false)
* `PGP_COMPRESSION_LEVEL`: set the compression level for the PGP encryption (0 - 9, default: 9)

## Scripts

This service includes [mu-cli](https://github.com/mu-semtech/mu-cli) scripts for key and configuration management:
* `gen-privkey`: Generate a new elliptic curve GPG key for use with mu-tunnel
* `gen-pubkey`: Convert a private GPG key file into a public GPG key file.
* `config-self`: Configure this tunnel service by changing the settings of the key.
* `config-peer`: Configure the peers this service connects to.

## Keys [for OpenPGP encryption used in the tunnel]

RSA and other algorithms over integer fields can be quite slow, as they require very large keys. Elliptic curves offer similar security with smaller key sizes (256 bits instead of 4096 bits) and are thus much faster.

Therefore it is recommended to use elliptic curve keys with this service. Modern versions of `gpg` support elliptic curves, but the `--expert` flag must be passed to generate these keys.

Curve25519 is a widely used elliptic curve which is also [rigid](https://safecurves.cr.yp.to/rigid.html), unlike the NIST curves. It is thus a good choice.

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

## Performance

Because this tunnel can see a lot of usage in the future, some performance testing might indicate a throughput bottleneck. Here is a summary of some basic tests taken on a 2-core (4-core with SMT) CPU. The specific details are not that important as these performance tests will merely give an indication of throughput.

### Large request

On large requests, the tunnel has a throughput of about 0.90MB/s. CPU usage was around 25% with peaks to 35%. RAM usage was up to 1.5GB.

A 'large' request was constructed by creating a string with random text of about 10MB. This string serves as the body of a simple POST request. This request is sent to the outgoing tunnel service, which encrypts the data, uses compression to try to reduce file size, sends it to the other tunnel service, which decrypts the message and sends it to the destination service. The destination service responds by just echoing the request and all the data is sent back to the source service. 10 large requests were executed sequentially, meaning around 200MB was sent over the tunnel with little overhead in the source and destination services.

The CPU usage can be explained. JavaScript (Node.js) is mostly single threaded, apart for some IO and things. The cryptography runs in (not native) JavaScript libraries which limits the CPU usage to 25% (one CPU core in full use). Peaks to 35% can be observed because at certain points in time, one service is sending a request while the other is receiving due to the data not fitting in a single ethernet frame. The overall high CPU usage is because of the compute intensive encryption operations. High RAM usage can be explained by the encryption and compression algorithms requiring large amounts of space.

### Small requests

On small requests, the tunnel has a throughput of about 167requests/s. CPU usage was about 2%, and RAM usage not significantly more than a few 10MB's.

A small request is constructed with little or no data in the body, and a few or no special headers. Each request is less than a KB of data. The request path is the sames as described in the previous section. In total, 48000 request were sent through the tunnel in this test setup.

The CPU usage is very low in this case. This can be explained by overhead. Encryption is a relative small part of the total compute time for these small requests.

In the real world, the throughput will be between the measurements for large and small requests and might differ significantly on other systems. When using other encryption algorithms, Node.js could potentially opt for using more native encryption libraries wich could provide better throughput.

