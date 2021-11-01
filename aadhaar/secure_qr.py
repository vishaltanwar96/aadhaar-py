import re
import zlib
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict


class MalformedDataReceived(Exception):
    pass


class Gender(Enum):
    MALE = "Male"
    FEMALE = "Female"
    TRANSGENDER = "Transgender"


@dataclass(frozen=True)
class ReferenceId:
    last_four_aadhaar_digits: str
    timestamp: datetime


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


class ExtractData:
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

    def _find_indexes_of_255_delimiters(self) -> list[int]:
        return [index for (index, value) in enumerate(self._data) if value == 255]

    def _make_reference_id(self, extracted_data: str) -> ReferenceId:
        return ReferenceId(
            last_four_aadhaar_digits=extracted_data[:4],
            timestamp=datetime.strptime(extracted_data[4:], "%Y%m%d%H%M%S%f"),
        )

    def _select_gender(self, extracted_data: str) -> Gender:
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

    def _extract_text_data(self, indexes: list[int]) -> Dict[str, str]:
        raw_extracted_data = {}
        previous = self._data.find(255) + 1
        for detail, index_position in zip(self._details, indexes):
            extracted_detail = self._data[previous:index_position].decode(
                self._ENCODING_TO_USE,
            )
            raw_extracted_data[detail] = extracted_detail
            previous = index_position + 1
        return raw_extracted_data
