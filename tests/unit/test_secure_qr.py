from unittest import TestCase

from aadhaar.secure_qr import SecureQRCodeCompressedBytesData


class TestQRCodeCompressedBytesData(TestCase):
    def test_has_qr_code_compressed_bytes_data_class(self) -> None:
        scanned_integer_data = 12345
        SecureQRCodeCompressedBytesData(scanned_integer_data)
