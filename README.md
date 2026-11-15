# levee

A stable front for a Puddle. Not built yet.

Someone rents a Levee, or runs one on a VPS of their own, and their Puddle does its Puddle communications through it:
friends add them by **the Levee's address** instead of the Puddle's, so it stays the same when their home network
changes, and the Puddle needs no open ports (it connects out to the Levee). The Levee **spools** what arrives while the
Puddle is offline and delivers it when it reconnects, and spools what the Puddle sends to friends who are away. **All
chats stay on the Puddle**: a Levee holds only what is in transit, and decrypts and signs nothing in the Puddle's name.

It is not a service for ordinary users: a headless daemon with no GUI, configured by a file, for someone reasonably
competent to run (the sort who would run a mail relay or a TURN server).

## The protocol

A Levee speaks the Puddle Protocol (`ezp2p/protocol`; check it out beside this repository as `../protocol`):

- **01 identity**: it checks the key chains of the Puddles it serves, and has an Ed25519 key of its own
  (`base32(SHA-256("puddle-levee-v1\n" || public key))`).
- **02 signatures**: it checks request signatures, and passes `X-Puddle-Signature` and `X-Puddle-Receipt` through
  untouched. It must pass the protocol's test vectors (`../protocol/vectors`).
- **06 Levee**: the part made for it. Above all, how a Levee fits *proving who answers*, which it would otherwise break
  (a sender would see the Levee's certificate and call it interception): the Puddle signs its receipts over the Levee's
  certificate, announces its Levee in its signed address record, and while the Puddle is away the Levee answers one-way
  requests with a **custody receipt** of its own (`X-Puddle-Custody`), which senders accept only from the Levee that
  Puddle announced.

The design draft, with the questions still open (credentials, how many Puddles per Levee, quotas, how long things are
held), is Puddle's `docs/levee.md`.

## When it is built

`../protocol/decisions.md` says to revisit sharing code when Levee is built: if it is C++ like Puddle and Pond, the
few hundred lines that check ids, chains, request signatures and receipts are worth extracting from Puddle into a small
library all three use, rather than written a third time.
