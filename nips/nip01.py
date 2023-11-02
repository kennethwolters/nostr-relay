"""
This module is an implementation of NIP-01. NIP-01 describes the Nostr protocol.
Source: https://raw.githubusercontent.com/nostr-protocol/nips/master/01.md
"""

import json
import hashlib

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
    Describes a Nostr event.

    Attributes:
        id (str): The event id.
        pubkey (str): The event creator's public key.
        created_at (int): The unix timestamp in seconds.
        kind (int): The event kind.
        tags (list): The event tags.
        content (str): The event content.
        sig (str): The event signature.
    """

    def __init__(
        self,
        pubkey: str,
        created_at: int,
        kind: int,
        tags: list = [""],
        content: str = "",
    ) -> None:
        self.pubkey: str = pubkey
        self.created_at: int = created_at
        self.kind: int = kind
        self.tags: list = tags
        self.content: str = content
        self.id: str = self._create_id()
        self.sig: str

    def _create_id(self) -> None:
        """
        To obtain the event.id, we sha265 the serialized event.
        """

        encoded_serialized_event_string = (
            self._get_serialised_utf8encoded_string_from_event()
        )
        hash_object = hashlib.sha256()
        hash_object.update(encoded_serialized_event_string)
        hex_hash = hash_object.hexdigest()

        self.id = hex_hash
        return hex_hash

    def _create_sig(self) -> None:
        """
        To obtain the event.sig, we sign the serialized event with the
        event.pubkey.
        """

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