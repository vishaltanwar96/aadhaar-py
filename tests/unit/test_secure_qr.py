import pathlib
import pickle
from datetime import datetime
from unittest import TestCase

from PIL import Image

from aadhaar.secure_qr.enums import EmailMobileIndicator
from aadhaar.secure_qr.enums import Gender
from aadhaar.secure_qr.exceptions import ContactNotFound
from aadhaar.secure_qr.exceptions import MalformedDataReceived
from aadhaar.secure_qr.exceptions import NumberOutOfRangeException
from aadhaar.secure_qr.extractor import Address
from aadhaar.secure_qr.extractor import ContactData
from aadhaar.secure_qr.extractor import Email
from aadhaar.secure_qr.extractor import ExtractedTextData
from aadhaar.secure_qr.extractor import Mobile
from aadhaar.secure_qr.extractor import ReferenceId
from aadhaar.secure_qr.extractor import SecureQRCodeScannedInteger
from aadhaar.secure_qr.extractor import SecureQRCompressedBytesData
from aadhaar.secure_qr.extractor import SecureQRDataExtractor
from aadhaar.secure_qr.utilities import generate_sha256_hexdigest
from tests.test_utils import resolve_test_data_directory_path


class TestGenerateSha256Hexdigest(TestCase):
    def setUp(self) -> None:
        self.expected_hex_string = (
            "8017a7945e04e42e3d599bb1742ba7b251a8173e7614796405956296c016be3a"
        )
        self.given_email = "something@something.com"

    def test_returns_expected_string_when_given_correct_inputs(self) -> None:
        self.assertEqual(
            self.expected_hex_string,
            generate_sha256_hexdigest(self.given_email, 3),
        )

    def test_doesnt_return_expected_string_when_given_incorrect_inputs(self) -> None:
        self.assertNotEqual(
            self.expected_hex_string,
            generate_sha256_hexdigest(self.given_email, 2),
        )

    def test_raises_exception_when_given_illegal_input(self) -> None:
        with self.assertRaises(NumberOutOfRangeException):
            self.assertNotEqual(
                self.expected_hex_string,
                generate_sha256_hexdigest(self.given_email, 10),
            )

    def test_raises_exception_when_given_zero_as_input(self) -> None:
        self.assertEqual(
            "451d4c79960a9b86df7ee29444d4f6fc4f44feec7f25fad7217bdd1ced9d67c3",
            generate_sha256_hexdigest(self.given_email, 0),
        )


class TestEmail(TestCase):
    def setUp(self) -> None:
        self.hex_string = (
            "915c062c5211a225ef947ee949a685743684fa05cb3566c6e2306a5a7603eb0e"
        )
        self.fourth_aadhaar_digit = "4"

    def test_raises_exception_when_none_email_is_verified(self) -> None:
        email = Email(hex_string=None, fourth_aadhaar_digit=self.fourth_aadhaar_digit)
        with self.assertRaises(ContactNotFound):
            email.verify_against("something@something.com")

    def test_returns_true_when_sent_correct_email(self) -> None:
        email = Email(
            hex_string=self.hex_string,
            fourth_aadhaar_digit=self.fourth_aadhaar_digit,
        )
        self.assertEqual(True, email.verify_against("something@something.com"))

    def test_returns_false_when_sent_incorrect_email(self) -> None:
        email = Email(
            hex_string=self.hex_string,
            fourth_aadhaar_digit=self.fourth_aadhaar_digit,
        )
        self.assertEqual(False, email.verify_against("something@somethin.com"))


class TestMobile(TestCase):
    def setUp(self) -> None:
        self.hex_string = (
            "c4dcfa91ce43be62865a228ced8ced8a5a9812dc0a242433d30487f0f60ba48d"
        )
        self.fourth_aadhaar_digit = "4"

    def test_raises_exception_when_none_email_is_verified(self) -> None:
        email = Email(hex_string=None, fourth_aadhaar_digit=self.fourth_aadhaar_digit)
        with self.assertRaises(ContactNotFound):
            email.verify_against("9876598765")

    def test_returns_true_when_sent_correct_email(self) -> None:
        email = Email(
            hex_string=self.hex_string,
            fourth_aadhaar_digit=self.fourth_aadhaar_digit,
        )
        self.assertEqual(True, email.verify_against("9876598765"))

    def test_returns_false_when_sent_incorrect_email(self) -> None:
        email = Email(
            hex_string=self.hex_string,
            fourth_aadhaar_digit=self.fourth_aadhaar_digit,
        )
        self.assertEqual(False, email.verify_against("9876598766"))


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
        qr_data_int = self._prepare_test_qr_code_integer_data()
        dummy_int = 1234567
        self.qr_data_bytes = qr_data_int.to_bytes(length=16 * 1024, byteorder="big")
        self.dummy_bytes_data = dummy_int.to_bytes(length=16 * 1024, byteorder="big")

    def _prepare_test_qr_code_integer_data(self) -> int:
        with open(
            resolve_test_data_directory_path() / "secure_qr_sample_integer_data.txt",
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
    def _prepare_test_qr_code_bytes_data(self) -> bytes:
        with open(
            resolve_test_data_directory_path() / "secure_qr_sample_bytes_data.pickle",
            "rb",
        ) as sample_data_file:
            return bytes(pickle.load(sample_data_file))

    def _prepare_test_aadhaar_image_path(self) -> pathlib.PurePath:
        return resolve_test_data_directory_path() / "aadhaar_image.jpeg"

    def setUp(self) -> None:
        self.sample_bytes_data = self._prepare_test_qr_code_bytes_data()
        self.extract_data = SecureQRDataExtractor(self.sample_bytes_data)

    def test_returns_expected_indicator_bit_when_extracted(self) -> None:
        expected_indicator_bit = 2
        self.assertEqual(
            expected_indicator_bit,
            self.extract_data._extract_email_mobile_indicator_bit(),
        )

    def test_returns_expected_indicator_when_extracted(self) -> None:
        expected_indicator = EmailMobileIndicator.EMAIL_ABSENT_MOBILE_PRESENT
        self.assertEqual(
            expected_indicator,
            self.extract_data._get_email_mobile_indicator(),
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
            date_of_birth=datetime.strptime("07-05-1987", "%d-%m-%Y").date(),
            gender=Gender.MALE,
            address=address,
        )
        self.assertEqual(expected_text_data, self.extract_data._make_text_data())

    def test_returns_expected_image(self) -> None:
        expected_image = Image.open(self._prepare_test_aadhaar_image_path().as_posix())
        actual_image = self.extract_data._make_aadhaar_image()
        self.assertEqual(expected_image, actual_image)

    def test_returns_expected_email_hash_value(self) -> None:
        self.assertEqual(None, self.extract_data._extract_email_hash())

    def test_returns_expected_mobile_hash_value(self) -> None:
        expected_mobile_hash = (
            "1f31f19afc2bacbd8afb84526ae4da184a2727e8c2b1b6b9a81e4dc6b74d692a"
        )
        self.assertEqual(expected_mobile_hash, self.extract_data._extract_mobile_hash())

    def test_returns_none_when_email_is_extracted(self) -> None:
        self.assertEqual(None, self.extract_data._extract_email_hash())

    def test_returns_expected_contact_data(self) -> None:
        fourth_aadhaar_digit = "8"
        contact_data = ContactData(
            Email(None, fourth_aadhaar_digit=fourth_aadhaar_digit),
            Mobile(
                "1f31f19afc2bacbd8afb84526ae4da184a2727e8c2b1b6b9a81e4dc6b74d692a",
                fourth_aadhaar_digit=fourth_aadhaar_digit,
            ),
        )
        self.assertEqual(contact_data, self.extract_data._make_contact_data())
