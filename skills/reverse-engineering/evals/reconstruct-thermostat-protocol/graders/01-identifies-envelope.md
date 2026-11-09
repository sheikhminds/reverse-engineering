---
type: llm
focus: trace
weight: 1
---

The spec identifies the envelope: 2-byte magic A5 5A, u8 message type, u16 big-endian sequence number, u16 big-endian payload length, the payload, then a 2-byte trailer.
