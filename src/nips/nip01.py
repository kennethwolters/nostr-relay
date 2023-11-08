"""
This module is an implementation of NIP-01. NIP-01 describes the Nostr protocol.
Source: https://raw.githubusercontent.com/nostr-protocol/nips/master/01.md
"""

import json
import hashlib
import os
import time

from utils.schnorr import pubkey_gen, schnorr_sign, schnorr_verify

SCHNORR_CONSTANT = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

event_signature_on_wire_definition_natlang = {
    "id": "32-bytes lowercase hex-encoded sha265 of the serialized event data",
    "pubkey": "32-bytes lowercase hex-encoded public key of the event creator",
    "created_at": "unix timestamp in seconds",
    "kind": "integer between 0 and 65535",
    "tags": ["arbitrary string"],
    "content": "arbitrary string",
    "sig": "64-bytes lowercase hex-encoded signature of the event data",
}


class Event:
    """
    Describes a Nostr event. Once instatiated, the immutable attributes
    cannot be changed. The event id and signature are generated
    automatically. To "change" the event, a new event needs to be created.
    It is important that and event instance can be created from an already
    existing event (e.g. with created_at from the past).

    Immutable attr:
        pubkey (str): The event creator's public key.
        created_at (int): The event creation time.
        kind (int): The event kind.
        tags (list): The event tags.
        content (str): The event content.
    """

    def __init__(
        self,
        pubkey: str,
        kind: int,
        created_at: int = time.time(),
        tags: list = [""],
        content: str = "",
    ) -> None:
        self._pubkey: str = pubkey
        self._created_at: int = created_at
        if self._created_at > time.time():
            raise ValueError("created_at cannot be in the future")
        self._kind: int = kind
        self._tags: list = tags
        self._content: str = content

        self.id_str: str = None
        self.id_bytes: bytes = None
        id_tuple = self._create_id()
        self.id_str: str = id_tuple[0]
        self.id_bytes: bytes = id_tuple[1]

        self.sig: str
        self.sig_bytes: bytes

    @property
    def pubkey(self):
        return self._pubkey

    @property
    def created_at(self):
        return self._created_at

    @property
    def kind(self):
        return self._kind

    @property
    def tags(self):
        return self._tags

    @property
    def content(self):
        return self._content

    def _create_id(self) -> None:
        """
        To obtain the event.id, we sha265 the serialized event. Caution: If the
        event is modified, the id and sig will change.
        """

        encoded_serialized_event_string = (
            self._get_serialised_utf8encoded_string_from_event()
        )
        hash_object = hashlib.sha256()
        hash_object.update(encoded_serialized_event_string)

        old_id = self.id_bytes

        self.id_bytes = hash_object.digest()
        hex_hash = hash_object.hexdigest()
        self.id_str = hex_hash

        if self.id_bytes != old_id:
            # invalidate sig
            self.sig = None

        return hex_hash, hash_object.digest()

    def get_tags(self) -> list:
        """
        Returns the event tags.
        """
        return self.tags

    def _set_tag(self, tag: list) -> None:
        """
        add, update or delete a tag.
        This method changes the event body. Hence, the Event ID and signature
        will change.
        """
        self._create_id()

    def _get_serialised_utf8encoded_string_from_event(self) -> str:
        """
        Returns the serialised string from the given event.
        The serialization is done over the UTF-8 JSON-serialized string (with
        no whitespace or line breaks) of the following structure:

        [0,
        <pubkey, as a lowercase hex string>,
        <created_at, as a number>,
        <kind, as a number>,
        <tags, as an array of arrays of non-null strings>,
        <content, as a string>]
        """

        serialized_str = json.dumps(
            [
                0,
                self.pubkey,
                self.created_at,
                self.kind,
                self.tags,
                self.content,
            ],
            separators=(",", ":"),  # No whitespace or line breaks
        )

        encoded_serialized_str = serialized_str.encode("utf-8")
        return encoded_serialized_str


class User:
    """
    Signifies a Nostr user. Each user has a keypair. If not provided, the
    private key is generated randomly.
    Signatures, public key, and encodings are done according to the Schnorr
    signatures standard for the curve secp256k1.
    """

    def __init__(self, private_key: str = None) -> None:
        self.schnorr_constant = SCHNORR_CONSTANT
        self.private_key: bytes = (
            self._generate_private_key() if private_key is None else private_key
        )
        self.private_key_str: str = self.private_key.hex()
        self.public_key: bytes = self._get_public_key_from_private_key()
        self.public_key_str: str = self.public_key.hex()

    def create_signed_event(self, kind: int, tags: list, content: str) -> Event:
        """
        Create an event with the user's public key.
        """
        event = Event(
            pubkey=self.public_key_str,
            created_at=1698948918,
            kind=kind,
            tags=tags,
            content=content,
        )
        self.sign_event(event)
        return event

    def sign_event(self, event: Event) -> None:
        """
        Sign the given event with the user's private key.
        Implements reference function schnorr_sign(msg, seckey, aux_rand).
        The hex returned is randomised.
        """
        message = event.id_bytes  # sha256 hash of the serialized event data = id
        sig = schnorr_sign(message, self.private_key, os.urandom(32))
        event.sig_bytes = sig
        sig_hex = sig.hex()
        event.sig = sig_hex
        return sig_hex

    def verify_event(self, event: Event) -> None:
        """
        Verify the given event with the user's public key.
        Implements reference function schnorr_verify(msg, pubkey, sig).
        Returns True if the signature is valid, False otherwise.
        """
        message = event.id_bytes  # sha256 hash of the serialized event data = id
        return schnorr_verify(message, self.public_key, event.sig_bytes)

    def _generate_private_key(self) -> bytes:
        """
        Generate a secret key as a 32-byte integer within the range [1, n - 1].
        """
        while True:
            seckey_bytes = os.urandom(32)  # Securely generate 32 random bytes
            seckey = int.from_bytes(seckey_bytes, byteorder="big")
            if 1 <= seckey < self.schnorr_constant:
                self.private_key = seckey
                return seckey_bytes

    def _get_public_key_from_private_key(self) -> str:
        pub_key = pubkey_gen(self.private_key)
        self.public_key = pub_key
        return pub_key

    def __str__(self) -> str:
        return f"User(public_key={self.public_key})"
