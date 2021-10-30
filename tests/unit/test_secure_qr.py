import pathlib
from unittest import TestCase

from aadhaar.secure_qr import MalformedDataReceived
from aadhaar.secure_qr import SecureQRCodeScannedInteger


class TestSecureQRCodeScannedInteger(TestCase):
    def _prepare_qr_integer_data(self) -> int:
        current_file = pathlib.Path(__file__).resolve()
        project_root = current_file.parent.parent.parent
        with open(
            project_root / "test_data" / "secure_qr_data.txt",
        ) as sample_data_file:
            sample_data = sample_data_file.read()
        return int(sample_data)

    def setUp(self) -> None:
        dummy_int = 1234567
        qr_data_int = self._prepare_qr_integer_data()
        self.dummy_scanned_integer = SecureQRCodeScannedInteger(dummy_int)
        self.qr_scanned_integer = SecureQRCodeScannedInteger(qr_data_int)

    def test_contains_expected_data_in_decompressed_bytes_data(self) -> None:
        expected_data = b"Penumarthi"
        self.assertIn(expected_data, self.qr_scanned_integer.decompress())

    def test_raises_exception_when_given_dummy_data(self) -> None:
        with self.assertRaises(MalformedDataReceived):
            self.dummy_scanned_integer.decompress()
