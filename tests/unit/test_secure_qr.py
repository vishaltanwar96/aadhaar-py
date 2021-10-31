import pathlib
from unittest import TestCase

from aadhaar.secure_qr import ExtractData
from aadhaar.secure_qr import MalformedDataReceived
from aadhaar.secure_qr import SecureQRCodeScannedInteger
from aadhaar.secure_qr import SecureQRCompressedBytesData


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
    def setUp(self) -> None:
        qr_data_int = self._prepare_test_qr_code_data()
        dummy_int = 1234567
        self.qr_data_bytes = qr_data_int.to_bytes(length=16 * 1024, byteorder="big")
        self.dummy_bytes_data = dummy_int.to_bytes(length=16 * 1024, byteorder="big")

    def _prepare_test_qr_code_data(self) -> int:
        current_file = pathlib.Path(__file__).resolve()
        project_root = current_file.parent.parent.parent
        with open(
            project_root / "test_data" / "secure_qr_data.txt",
        ) as sample_data_file:
            sample_data = sample_data_file.read()
        return int(sample_data)

    def test_contains_expected_data_in_decompressed_bytes_data(self) -> None:
        expected_data = b"Penumarthi"
        compressed_bytes_data = SecureQRCompressedBytesData(self.qr_data_bytes)
        self.assertIn(expected_data, compressed_bytes_data.decompress())

    def test_raises_exception_when_given_dummy_data(self) -> None:
        compressed_bytes_data = SecureQRCompressedBytesData(self.dummy_bytes_data)
        with self.assertRaises(MalformedDataReceived):
            compressed_bytes_data.decompress()


class TestExtractData(TestCase):
    def test_has_method_to_extract_email_mobile_indicator_bit(self) -> None:
        extract_data = ExtractData()
        extract_data.extract_email_mobile_indicator_bit()
