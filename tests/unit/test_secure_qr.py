from unittest import TestCase

from aadhaar.secure_qr import SecureQRCodeScannedInteger, SecureQRCompressedBytesData


class TestSecureQRCodeScannedInteger(TestCase):
    def setUp(self) -> None:
        data = 12345
        self.scanned_integer = SecureQRCodeScannedInteger(data)
        self.bytes_data = data.to_bytes(length=16 * 1024, byteorder="big")

    def test_converts_to_bytes_from_integer(self) -> None:
        self.assertIsInstance(self.scanned_integer.convert_to_bytes(), bytes)

    def test_expects_converted_bytes_to_be_equal_to_setup_bytes_data(self) -> None:
        self.assertEqual(self.bytes_data, self.scanned_integer.convert_to_bytes())


class TestSecureQRCompressedBytesData(TestCase):
    def test_has_decompress_method(self) -> None:
        compressed_bytes_data = SecureQRCompressedBytesData(b"\x00")
        compressed_bytes_data.decompress()
