# Mu-tunnel

This README will be updated when the project has made some progress and the features are more fixed.

## To-do's

This mu-tunnel (as forked from the original mu-tunnel) is more specified for mu.semte.ch stacks. This means we can rely on core assumptions. An overview of the assumptions and mechanisms behind this mu-tunnel:

*	The presence of an identifier or dispatcher where all trafic will be routed to on both ends of the tunnel
*	The tunnel is symmetric: there can be communication in both directions
*	There are only 2 endpoints on this tunnel  
	For communicating to multiple stacks, use multiple tunnels
*	No more encapsulation of requests, this tunnel acts more like a HTTP-proxy for the identifier/dispatcher than a forwarder of messages

The rest of this file is taken from the original mu-tunnel.

## HTTPS

This service *must be ran over HTTPS for strong security*. Without HTTPS messages can easily be intercepted and replayed at a later date, due to PGPs one-pass nature.

## Scripts

This service includes [https://github.com/mu-semtech/mu-cli](mu-cli) scripts for key and configuration management:
* `gen-privkey`: Generate a new elliptic curve GPG key for use with mu-tunnel
* `gen-pubkey`: Convert a private GPG key file into a public GPG key file.
* `config-self`: Configure this tunnel service by changing the settings of the key.
* `config-peer`: Configure the peers this service connects to.

## Keys

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

