import tempfile
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .transfer_crypto import decrypt_file, encrypt_file


class TransferCryptoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.agent_b = X25519PrivateKey.generate()

    def tearDown(self):
        self.tmp.cleanup()

    def test_only_destination_key_can_decrypt(self):
        clear = self.root / "clear.bin"
        envelope = self.root / "exchange.clx"
        clear.write_bytes(b"private payload\x00\xff")
        encrypt_file(clear, envelope, recipient="agent-b", sender="gateway",
                     recipient_key=self.agent_b.public_key())

        with self.assertRaises(PermissionError):
            decrypt_file(envelope, self.root / "wrong-recipient", recipient="agent-a",
                         private_key=X25519PrivateKey.generate(), max_bytes=1024)
        with self.assertRaises(InvalidTag):
            decrypt_file(envelope, self.root / "wrong-key", recipient="agent-b",
                         private_key=X25519PrivateKey.generate(), max_bytes=1024)

        output = self.root / "output.bin"
        decrypt_file(envelope, output, recipient="agent-b",
                     private_key=self.agent_b, max_bytes=1024)
        self.assertEqual(output.read_bytes(), clear.read_bytes())

    def test_rejects_plaintext_and_oversize(self):
        plain = self.root / "plain.bin"
        plain.write_bytes(b"not encrypted")
        with self.assertRaisesRegex(ValueError, "non cifrato"):
            decrypt_file(plain, self.root / "out", recipient="agent-b",
                         private_key=self.agent_b, max_bytes=1024)

        envelope = self.root / "large.clx"
        encrypt_file(plain, envelope, recipient="agent-b", sender="gateway",
                     recipient_key=self.agent_b.public_key())
        with self.assertRaisesRegex(ValueError, "oltre il limite"):
            decrypt_file(envelope, self.root / "out", recipient="agent-b",
                         private_key=self.agent_b, max_bytes=1)

    def test_binary_larger_than_50mb_roundtrips_streaming(self):
        clear = self.root / "large.bin"
        block = bytes(range(256)) * 4096  # 1 MiB non comprimibile dal protocollo
        with clear.open("wb") as stream:
            for _ in range(51):
                stream.write(block)
        envelope = self.root / "large.clx"
        output = self.root / "large.out"

        encrypt_file(clear, envelope, recipient="agent-b", sender="gateway",
                     recipient_key=self.agent_b.public_key())
        header = decrypt_file(envelope, output, recipient="agent-b",
                              private_key=self.agent_b, max_bytes=64 * 1024 * 1024)

        self.assertGreater(header["size"], 50 * 1024 * 1024)
        self.assertEqual(output.read_bytes(), clear.read_bytes())


if __name__ == "__main__":
    unittest.main()
