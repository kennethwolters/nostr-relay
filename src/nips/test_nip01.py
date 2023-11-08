"""
This module tests nip01.py. It enforces the NIP-01 specification.
"""

import unittest

from nips.nip01 import Event, User


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
            event.id_str,
            "f29994ceab5b631558e200a0b62ad485eaad8938ba1cdef5bbbff09a89b096e6",
        )


class TestUser(unittest.TestCase):
    """
    Test User class
    """

    def setUp(self) -> None:
        self.user = User()
        self.test_event = Event(
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
        self.private_key = self.user.private_key
        self.test_private_key_str = (
            "71552c92d6c1a3dd208d121ac6b44d51e0861751135a3ef70d5b15f5c1059ff1"
        )
        self.test_sig_str = "ee44b485dbf7b2d63601cb763c61e556adbc428b344793ce5a5db2f886fd94d9fafa4bb55c11e10ea44d9262beffa94b0491d8eadb2ff498cf40777b416c9a68"

    def test_sign_event_by_sig_structure(self) -> None:
        """
        Tests the User.sign_event(event = Event()) method.
        Since the signature is randomised, we will test that the signature
        a hex and that the signature is of the correct length.
        """
        self.user.sign_event(self.test_event)
        self.assertEqual(type(self.test_event.sig), str)
        self.assertEqual(self.is_hex(self.test_event.sig), True)
        self.assertEqual(len(self.test_event.sig), len(self.test_sig_str))

    def test_sign_event_by_validation(self) -> None:
        """
        Tests the User.sign_event(event = Event()) method.
        """
        self.user.sign_event(self.test_event)
        self.assertTrue(self.user.verify_event(self.test_event))

    def test_verify_event(self) -> None:
        """
        Tests the User.verify_event(event = Event()) method.
        """

    def test__get_public_key_from_private_key(self) -> None:
        """
        Running this test takes having a private key as a string.
        """

    def test_user_instantiation_with_existing_private_key(self) -> None:
        """
        Tests the User class instantiation with an existing private key.
        """

    def test_create_signed_event(self) -> None:
        """
        Tests the User.create_signed_event() method.
        """

    def is_hex(self, s):
        try:
            int(s, 16)
            return True
        except ValueError:
            return False
