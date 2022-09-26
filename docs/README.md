# `qorp-python` documentation

> **Warning**
> Both `QORP` and `qorp-python` are not production-ready!

## Contents

- [QORP](#qorp)
  - [Basic principes](#basic-principes)
    - [Route search](#route-search)
    - [Data transfer](#data-transfer)
    - [Route rejection](#route-rejection)
  - [Message types](#message-types)
    - [Data message](#data-message)
    - [Route request](#route-request-message)
    - [Route response](#route-response-message)
    - [Route error](#route-error-message)

## QORP

`QORP` (Quite Ok Routing Protocol) is simple reactive (on-demand) dynamic routing rotocol.

What it means?

- Dynamic routing
  > Main goal of QORP is to connect devices in the network by founding and using routes through
  > network's nodes.
- Reactivity
  > Nodes does hot holds full information about entire network. Theese information obtained only
  > when it is needed.

### Basic principes

#### Route search

If node wants to send some data to other node it is necessary to find out route to the destination.

To find route source node sends Route Request message to all its neighbours.
Then neighbours relay Route Request to their neighbours, and again and again until Route Request
arrives to destination node.
Destination node responds to Route Request with Route Response message. This message going back to
Route Request originator and informs it that it is a route to requested node.

> Both Route Request and Route Response contains a X25519 public key for shared secret derivation and
> further encrypt/decrypt data that will be trasfered over the network.

While node receives Route Response for sended Route Request it remembers direction from which it
arrives (neighbour node that sends theese Route Response) and calculates a key for symmetrical
encryption.

#### Data transfer

It's a simplest part of a whole protocol. After obtaining a secret (session/route) key nodes use
this key to encrypt data with ChaCha20Poly1305. After encryption node creates a Data message with
information about source and destintion and sends it to direction to target.

#### Route rejection

### Message types

#### Data message

#### Route request message

#### Route response message

#### Route error message
