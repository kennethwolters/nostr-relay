"""
This module tests nip01.py. It enforces the NIP-01 specification.
"""

import unittest

from nips.nip01 import Event


class TestEvent(unittest.TestCase):
    """
    Tests the Event class.
    """

    def test__get_serialised_utf8encoded_string_from_event(self) -> None:
        """
        Tests the Event._create_id() method.
        """

        # Arrange
        event = Event(
            pubkey="npub1sg6plzptd64u62a878hep2kev88swjh3tw00gjsfl8f237lmu63q0uf63m",
            created_at=1698948918,
            kind=42,
            tags=[
                [
                    "e",
                    "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36",
                    "wss://nostr.example.com",
                ]
            ],
            content="Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
        )

        # Act
        serialized_string = event._get_serialised_utf8encoded_string_from_event()

        # Assert
        self.assertEqual(
            serialized_string,
            b'[0,"npub1sg6plzptd64u62a878hep2kev88swjh3tw00gjsfl8f237lmu63q0uf63m",1698948918,42,[["e","5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36","wss://nostr.example.com"]],"Lorem ipsum dolor sit amet, consectetur adipiscing elit."]',
        )

    def test__create_id(self) -> None:
        """
        Tests the Event._create_id() method.
        """

        # Arrange
        event = Event(
            pubkey="npub1sg6plzptd64u62a878hep2kev88swjh3tw00gjsfl8f237lmu63q0uf63m",
            created_at=1698948918,
            kind=42,
            tags=[
                [
                    "e",
                    "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36",
                    "wss://nostr.example.com",
                ]
            ],
            content="Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
        )

        # Act
        event._create_id()

        # Assert
        self.assertEqual(
            event.id,
            "f29994ceab5b631558e200a0b62ad485eaad8938ba1cdef5bbbff09a89b096e6",
        )
