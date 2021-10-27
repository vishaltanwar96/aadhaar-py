from unittest import TestCase

from aadhaar.secure_qr import SecureQRCodeCompressedBytesData


class TestQRCodeCompressedBytesData(TestCase):
    def test_has_qr_code_compressed_bytes_data_class_has_method_to_compress_integer(
        self,
    ) -> None:
        compressed_bytes = SecureQRCodeCompressedBytesData(12345)
        compressed_bytes.compress()
