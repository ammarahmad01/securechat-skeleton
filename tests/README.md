# Tests and Evidence

This folder contains semi-automated tests, PCAP placeholders, and logs for Secure Chat Assignment 2.

## Test Summary

| Test         | Goal                         | Expected Outcome                       |
| ------------ | ---------------------------- | -------------------------------------- |
| Normal Chat  | Show ciphertext only         | PCAP shows encrypted ct (no plaintext) |
| Invalid Cert | Server rejects forged cert   | Error: BAD CERT                        |
| Tampering    | Signature invalidation       | Message dropped                        |
| Replay       | Replay detection             | Replay warning                         |
| Non-rep      | Offline receipt verification | Verified successfully                  |

## Running Tests

```powershell
python tests/run_all_tests.py
```

If `tshark` (Wireshark CLI) is available on PATH, tests will attempt to capture to `tests/pcaps/*.pcapng`. If not found, tests still run and log a note.

## Wireshark Display Filters

- Show encrypted chat packets:

```
tcp.port == 5000
```

- Filter by message frame content (may match JSON fragments):

```
tcp contains "msg"
```

- Confirm no plaintext content: use Find/Find Packet with your message text — it should not appear in payloads.
