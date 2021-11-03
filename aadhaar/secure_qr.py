import re
import zlib
from abc import ABC
from abc import abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from io import BytesIO
from typing import Optional

from PIL import Image


class MalformedDataReceived(Exception):
    pass


class ContactNotFound(Exception):
    pass


class Gender(Enum):
    MALE = "Male"
    FEMALE = "Female"
    TRANSGENDER = "Transgender"


class EmailMobileIndicator(Enum):
    EMAIL_MOBILE_BOTH_ABSENT = 0
    EMAIL_PRESENT_MOBILE_ABSENT = 1
    EMAIL_ABSENT_MOBILE_PRESENT = 2
    EMAIL_MOBILE_BOTH_PRESENT = 3


@dataclass(frozen=True)
class ReferenceId:
    last_four_aadhaar_digits: str
    timestamp: datetime


class ContactABC(ABC):
    @abstractmethod
    def verify_against(self, contact: str) -> bool:
        pass


class Email(ContactABC):
    def __init__(self, hex_string: Optional[str], reference_id: ReferenceId) -> None:
        self.hex_string = hex_string
        self._reference_id = reference_id

    def verify_against(self, contact: str) -> bool:
        if self.hex_string is None:
            raise ContactNotFound("Email not found in the provided data.")
        return True


@dataclass(frozen=True)
class Address:
    care_of: str
    district: str
    landmark: str
    house: str
    location: str
    pin_code: str
    post_office: str
    state: str
    street: str
    sub_district: str
    vtc: str


@dataclass(frozen=True)
class ExtractedTextData:
    reference_id: ReferenceId
    name: str
    date_of_birth: datetime
    gender: Gender
    address: Address


class SecureQRCodeScannedInteger:
    def __init__(self, data: int) -> None:
        self._data = data

    def convert_to_bytes(self) -> bytes:
        return self._data.to_bytes(byteorder="big", length=16 * 1024)


class SecureQRCompressedBytesData:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def _remove_null_bytes_from_left(self) -> bytes:
        return self._data.lstrip(b"\x00")

    def decompress(self):
        bytes_data = self._remove_null_bytes_from_left()
        try:
            decompressed_bytes_data = zlib.decompress(
                bytes_data,
                wbits=zlib.MAX_WBITS + 15,
            )
        except zlib.error:
            raise MalformedDataReceived(
                "Decompression failed, Please provide valid data.",
            )
        return decompressed_bytes_data


class SecureQRDataExtractor:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._ENCODING_TO_USE = "ISO-8859-1"
        self._details = [
            "reference_id",
            "name",
            "dob",
            "gender",
            "care_of",
            "district",
            "landmark",
            "house",
            "location",
            "pincode",
            "post_office",
            "state",
            "street",
            "sub_district",
            "vtc",
        ]

    def _extract_email_mobile_indicator_bit(self) -> int:
        return int(self._data[0 : self._data.find(255)].decode(self._ENCODING_TO_USE))

    def _get_email_mobile_indicator(self) -> EmailMobileIndicator:
        return EmailMobileIndicator(self._extract_email_mobile_indicator_bit())

    def _find_indexes_of_255_delimiters(self) -> list[int]:
        return [index for (index, value) in enumerate(self._data) if value == 255]

    @staticmethod
    def _make_reference_id(extracted_data: str) -> ReferenceId:
        return ReferenceId(
            last_four_aadhaar_digits=extracted_data[:4],
            timestamp=datetime.strptime(extracted_data[4:], "%Y%m%d%H%M%S%f"),
        )

    @staticmethod
    def _select_gender(extracted_data: str) -> Gender:
        if re.match(pattern=r"m|male", string=extracted_data, flags=re.IGNORECASE):
            return Gender.MALE
        elif re.match(pattern=r"f|female", string=extracted_data, flags=re.IGNORECASE):
            return Gender.FEMALE
        return Gender.TRANSGENDER

    def _make_text_data(self) -> ExtractedTextData:
        indexes = self._find_indexes_of_255_delimiters()
        extracted_text_data = self._extract_text_data(indexes[1:])
        return ExtractedTextData(
            name=extracted_text_data["name"],
            reference_id=self._make_reference_id(extracted_text_data["reference_id"]),
            gender=self._select_gender(extracted_text_data["gender"]),
            date_of_birth=datetime.strptime(extracted_text_data["dob"], "%d-%m-%Y"),
            address=Address(
                care_of=extracted_text_data["care_of"],
                district=extracted_text_data["district"],
                landmark=extracted_text_data["landmark"],
                house=extracted_text_data["house"],
                location=extracted_text_data["location"],
                pin_code=extracted_text_data["pincode"],
                post_office=extracted_text_data["post_office"],
                state=extracted_text_data["state"],
                street=extracted_text_data["street"],
                sub_district=extracted_text_data["sub_district"],
                vtc=extracted_text_data["vtc"],
            ),
        )

    def _extract_text_data(self, indexes: list[int]) -> dict[str, str]:
        raw_extracted_data = {}
        previous = self._data.find(255) + 1
        for detail, index_position in zip(self._details, indexes):
            extracted_detail = self._data[previous:index_position].decode(
                self._ENCODING_TO_USE,
            )
            raw_extracted_data[detail] = extracted_detail
            previous = index_position + 1
        return raw_extracted_data

    def _extract_aadhaar_image(self) -> Image.Image:
        ending = len(self._data) - 256
        length_to_subtract = self._calculate_length_to_subtract()
        image_bytes = self._data[
            self._find_indexes_of_255_delimiters()[15] + 1 : ending - length_to_subtract
        ]
        return Image.open(BytesIO(image_bytes))

    def _calculate_length_to_subtract(self) -> int:
        email_mobile_indicator_bit = self._get_email_mobile_indicator()

        if email_mobile_indicator_bit is EmailMobileIndicator.EMAIL_MOBILE_BOTH_PRESENT:
            length_to_subtract = 32 * 2
        elif (
            email_mobile_indicator_bit
            is EmailMobileIndicator.EMAIL_ABSENT_MOBILE_PRESENT
        ) or (
            email_mobile_indicator_bit
            is EmailMobileIndicator.EMAIL_PRESENT_MOBILE_ABSENT
        ):
            length_to_subtract = 32 * 1
        else:
            length_to_subtract = 32 * 0
        return length_to_subtract

    def _extract_email_hash(self) -> Optional[str]:
        data_length = len(self._data)
        email_mobile_indicator = self._get_email_mobile_indicator()
        if (
            email_mobile_indicator is EmailMobileIndicator.EMAIL_MOBILE_BOTH_PRESENT
        ) or (
            email_mobile_indicator is EmailMobileIndicator.EMAIL_PRESENT_MOBILE_ABSENT
        ):
            return self._data[
                data_length - 256 - 32 - 32 : data_length - 256 - 32
            ].hex()
        return None

    def _extract_mobile_hash(self) -> Optional[str]:
        data_length = len(self._data)
        email_mobile_indicator = self._get_email_mobile_indicator()
        if (
            email_mobile_indicator is EmailMobileIndicator.EMAIL_MOBILE_BOTH_PRESENT
        ) or (
            email_mobile_indicator is EmailMobileIndicator.EMAIL_ABSENT_MOBILE_PRESENT
        ):
            return self._data[data_length - 256 - 32 : data_length - 256].hex()
        return None
