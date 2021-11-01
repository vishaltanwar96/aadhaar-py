import pathlib
from datetime import datetime
from unittest import TestCase

from aadhaar.secure_qr import Address
from aadhaar.secure_qr import ExtractData
from aadhaar.secure_qr import ExtractedTextData
from aadhaar.secure_qr import Gender
from aadhaar.secure_qr import MalformedDataReceived
from aadhaar.secure_qr import ReferenceId
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
            project_root / "test_data" / "secure_qr_sample_integer_data.txt",
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
    def _prepare_test_qr_code_data(self) -> str:
        current_file = pathlib.Path(__file__).resolve()
        project_root = current_file.parent.parent.parent
        with open(
            project_root / "test_data" / "secure_qr_sample_bytes_data.txt",
        ) as sample_data_file:
            sample_data = sample_data_file.read()
        return sample_data

    def setUp(self) -> None:
        self.sample_bytes_data = self._prepare_test_qr_code_data().encode("ISO-8859-1")
        self.extract_data = ExtractData(self.sample_bytes_data)

    def test_returns_expected_indicator_bit_when_extracted(self) -> None:
        expected_indicator_bit = 2
        self.assertEqual(
            expected_indicator_bit,
            self.extract_data._extract_email_mobile_indicator_bit(),
        )

    def test_returns_expected_list_of_255_delimiter_when_called(self) -> None:
        expected_list_of_255_delimiter = [
            index
            for (index, value) in enumerate(self.sample_bytes_data)
            if value == 255
        ]
        self.assertEqual(
            expected_list_of_255_delimiter,
            self.extract_data._find_indexes_of_255_delimiters(),
        )

    def test_returns_expected_extracted_text_data(self) -> None:
        reference_id = ReferenceId(
            last_four_aadhaar_digits="8908",
            timestamp=datetime.strptime("20190305150137123", "%Y%m%d%H%M%S%f"),
        )
        address = Address(
            care_of="S/O: Pattabhi Rama Rao",
            district="East Godavari",
            landmark="Near Siva Temple",
            house="4-83",
            location="Sctor-2",
            pin_code="533016",
            post_office="Aratlakatta",
            state="Andhra Pradesh",
            street="Main Road",
            sub_district="Karapa",
            vtc="Aratlakatta",
        )
        expected_text_data = ExtractedTextData(
            name="Penumarthi Venkat",
            reference_id=reference_id,
            date_of_birth=datetime.strptime("07-05-1987", "%d-%m-%Y"),
            gender=Gender.MALE,
            address=address,
        )
        self.assertEqual(expected_text_data, self.extract_data._make_text_data())
