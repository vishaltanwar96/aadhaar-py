import json
import pathlib
import pickle
from datetime import datetime
from unittest import TestCase

from aadhaar.secure_qr.enums import Gender
from aadhaar.secure_qr.exceptions import MalformedDataReceived
from aadhaar.secure_qr.extractor import Address
from aadhaar.secure_qr.extractor import ContactData
from aadhaar.secure_qr.extractor import Email
from aadhaar.secure_qr.extractor import ExtractedSecureQRData
from aadhaar.secure_qr.extractor import ExtractedTextData
from aadhaar.secure_qr.extractor import Mobile
from aadhaar.secure_qr.extractor import ReferenceId
from aadhaar.secure_qr.extractor import extract_data
from tests.test_utils import resolve_test_data_directory_path


class TestExtractFromAadhaar(TestCase):
    def _prepare_test_qr_code_integer_data(self) -> int:
        with open(
            resolve_test_data_directory_path() / "secure_qr_sample_integer_data.txt",
        ) as sample_data_file:
            sample_data = sample_data_file.read()
        return int(sample_data)

    def _prepare_test_aadhaar_image_path(self) -> pathlib.PurePath:
        return resolve_test_data_directory_path() / "aadhaar_image.pickle"

    def test_returns_expected_data_when_provided_correct_input(self) -> None:
        reference_id = ReferenceId(
            last_four_aadhaar_digits="8908",
            timestamp=datetime.strptime("20190305150137123", "%Y%m%d%H%M%S%f"),
        )
        contact_data = ContactData(
            Email(None, fourth_aadhaar_digit=reference_id.last_four_aadhaar_digits[3]),
            Mobile(
                "1f31f19afc2bacbd8afb84526ae4da184a2727e8c2b1b6b9a81e4dc6b74d692a",
                fourth_aadhaar_digit=reference_id.last_four_aadhaar_digits[3],
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
            date_of_birth=datetime.strptime("07-05-1987", "%d-%m-%Y").date(),
            gender=Gender.MALE,
            address=address,
        )
        with open(
            self._prepare_test_aadhaar_image_path().as_posix(),
            "rb",
        ) as pickled_image:
            expected_image = pickle.load(pickled_image)
        expected_data = ExtractedSecureQRData(
            contact_info=contact_data,
            image=expected_image,
            text_data=text_data,
        )
        actual_data = extract_data(self._prepare_test_qr_code_integer_data())
        assert actual_data.image.tobytes() == expected_image.tobytes()
        self.assertEqual(
            expected_data,
            actual_data,
        )

    def test_raises_malformed_data_received_exception_when_given_bad_input(
        self,
    ) -> None:
        with self.assertRaises(MalformedDataReceived):
            extract_data(12343453)

    def test_raises_attribute_error_when_given_str_input(self) -> None:
        with self.assertRaises(AttributeError):
            extract_data("12343453")  # type: ignore

    def test_returns_expected_extracted_data_using_to_dict(self) -> None:
        with open(resolve_test_data_directory_path() / "to_dict.json") as to_dict_json:
            expected_data = json.load(to_dict_json)
        extracted_data = extract_data(self._prepare_test_qr_code_integer_data())
        self.assertEqual(expected_data, extracted_data.to_dict())
