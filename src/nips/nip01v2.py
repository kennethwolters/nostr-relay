"""
This module is an implementation of NIP-01. NIP-01 describes the Nostr protocol.
Source: https://raw.githubusercontent.com/nostr-protocol/nips/master/01.md

Event object definition:
{
  "id": <32-bytes lowercase hex-encoded sha256 of the serialized event data>,
  "pubkey": <32-bytes lowercase hex-encoded public key of the event creator>,
  "created_at": <unix timestamp in seconds>,
  "kind": <integer between 0 and 65535>,
  "tags": [
    [<arbitrary string>...],
    ...
  ],
  "content": <arbitrary string>,
  "sig": <64-bytes lowercase hex of the signature of the sha256 hash of the serialized event data, which is the same as the "id" field>
}

"""

from dataclasses import dataclass
import json
import time
import hashlib
import os

from utils.schnorr import pubkey_gen, schnorr_sign, schnorr_verify


@dataclass
class Event:
    id: bytes
    pubkey: bytes
    created_at: int
    kind: int
    tags: list
    content: str
    sig: bytes


def create_event(
    private_key: bytes,
    public_key: bytes,
    kind: int,
    tags: list,
    content: str,
) -> Event:
    """
    Creates a signed event object.
    """

    created_at = int(time.time())
    serialized_event_body = serialize_event_body(
        public_key, created_at, kind, tags, content
    )
    event_id = hashlib.sha256(serialized_event_body).digest()
    signature = schnorr_sign(event_id, private_key, os.urandom(32))

    return Event(
        id=event_id,
        pubkey=public_key,
        created_at=created_at,
        kind=kind,
        tags=tags,
        content=content,
        sig=signature,
    )


def serialize_event_body(
    public_key: bytes,
    created_at: int,
    kind: int,
    tags: list,
    content: str,
) -> str:
    """
    Returns the serialised string from the given event body.
    The serialization is done over the UTF-8 JSON-serialized string (with
    no whitespace or line breaks) of the following structure:

    [0,<pubkey, as a lowercase hex string>,<created_at, as a number>,
    <kind, as a number>,<tags, as an array of arrays of non-null strings>,
    <content, as a string>]
    """

    # hex the public_key
    public_key = public_key.hex()

    serialized_str = json.dumps(
        [
            0,
            public_key,
            created_at,
            kind,
            tags,
            content,
        ],
        separators=(",", ":"),  # No whitespace or line breaks
    )

    encoded_serialized_str = serialized_str.encode("utf-8")
    return encoded_serialized_str


'''
Pretty clear that these are client-side functions, so I'm not going to bother

def create_private_key() -> bytes:
    """
    Returns a 32-byte private key.
    """
    return os.urandom(32)


def create_public_key(private_key: bytes) -> bytes:
    """
    Returns the public key for the given private key.
    """
    return pubkey_gen(private_key)

def verify_event(event: Event) -> bool:
    """
    Compare the signature of the given event with the public key using
    the schnorr_verify function.
    """

    return schnorr_verify(event.id, event.pubkey, event.sig)
'''
