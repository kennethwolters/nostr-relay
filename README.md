## Separation of Concerns between Client and Relay in the Nostr Protocol
| Responsibility    | Responsibility of ... | Further Explanation
| -------- | ------- | -------
| Create Private Key  | Client    |
| Create Public Key | Client     |
| Verify Event    | Client    |
| Create Event    | Client    |

With "relay", we mean a the server-prat of the Nostr-specification. In reality, a relay may be capable of actions that the client is responible.