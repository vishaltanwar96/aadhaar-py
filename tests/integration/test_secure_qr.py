import pathlib
from datetime import datetime
from unittest import TestCase

from PIL import Image

from aadhaar.secure_qr.enums import Gender
from aadhaar.secure_qr.exceptions import MalformedDataReceived
from aadhaar.secure_qr.extractor import Address
from aadhaar.secure_qr.extractor import ContactData
from aadhaar.secure_qr.extractor import Email
from aadhaar.secure_qr.extractor import ExtractedSecureQRData
from aadhaar.secure_qr.extractor import ExtractedTextData
from aadhaar.secure_qr.extractor import Mobile
from aadhaar.secure_qr.extractor import ReferenceId
from aadhaar.secure_qr.extractor import extract_data_from_secure_qr
from tests.test_utils import resolve_test_data_directory_path


class TestExtractFromAadhaar(TestCase):
    def _prepare_test_qr_code_integer_data(self) -> int:
        with open(
            resolve_test_data_directory_path() / "secure_qr_sample_integer_data.txt",
        ) as sample_data_file:
            sample_data = sample_data_file.read()
        return int(sample_data)

    def _prepare_test_aadhaar_image_path(self) -> pathlib.PurePath:
        return resolve_test_data_directory_path() / "aadhaar_image.jpeg"

    def test_returns_expected_data_when_provided_correct_input(self) -> None:
        reference_id = ReferenceId(
            last_four_aadhaar_digits="8908",
            timestamp=datetime.strptime("20190305150137123", "%Y%m%d%H%M%S%f"),
        )
        contact_data = ContactData(
            Email(None, reference_id=reference_id),
            Mobile(
                "1f31f19afc2bacbd8afb84526ae4da184a2727e8c2b1b6b9a81e4dc6b74d692a",
                reference_id=reference_id,
            ),
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
        text_data = ExtractedTextData(
            name="Penumarthi Venkat",
            reference_id=reference_id,
            date_of_birth=datetime.strptime("07-05-1987", "%d-%m-%Y"),
            gender=Gender.MALE,
            address=address,
        )
        expected_data = ExtractedSecureQRData(
            contact_info=contact_data,
            image=Image.open(self._prepare_test_aadhaar_image_path().as_posix()),
            text_data=text_data,
        )
        self.assertEqual(
            expected_data,
            extract_data_from_secure_qr(self._prepare_test_qr_code_integer_data()),
        )

    def test_raises_malformed_data_received_exception_when_given_bad_input(
        self,
    ) -> None:
        with self.assertRaises(MalformedDataReceived):
            extract_data_from_secure_qr(12343453)

    def test_raises_attribute_error_when_given_str_input(self) -> None:
        with self.assertRaises(AttributeError):
            extract_data_from_secure_qr("12343453")  # type: ignore
