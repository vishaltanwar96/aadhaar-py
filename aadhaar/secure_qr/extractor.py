import re
import zlib
from abc import ABC
from abc import abstractmethod
from base64 import b64encode
from dataclasses import asdict
from dataclasses import dataclass
from datetime import date
from datetime import datetime
from io import BytesIO
from typing import Optional
from typing import Union

from PIL import Image

from aadhaar.secure_qr.enums import EmailMobileIndicator
from aadhaar.secure_qr.enums import Gender
from aadhaar.secure_qr.exceptions import ContactNotFound
from aadhaar.secure_qr.exceptions import MalformedDataReceived
from aadhaar.secure_qr.utilities import generate_sha256_hexdigest

_SECURE_QR_ENCODING = "ISO-8859-1"


@dataclass(frozen=True)
class ReferenceId:
    last_four_aadhaar_digits: str
    timestamp: datetime

    def to_dict(self) -> dict[str, str]:
        reference_id_dict = asdict(self)
        reference_id_dict["timestamp"] = self.timestamp.isoformat()
        return reference_id_dict


class ContactABC(ABC):
    @abstractmethod
    def verify_against(self, contact: str) -> bool:
        pass


class ContactMixin:
    hex_string: Optional[str]
    fourth_aadhaar_digit: str

    def verify_against(self, contact: str) -> bool:
        if self.hex_string is None:
            raise ContactNotFound(
                f"{self.__class__.__name__} not found in provided data",
            )
        return self.hex_string == generate_sha256_hexdigest(
            contact,
            int(self.fourth_aadhaar_digit),
        )

    def to_dict(self) -> dict[str, Optional[str]]:
        return {"hex_string": self.hex_string}


@dataclass(frozen=True)
class Email(ContactMixin, ContactABC):
    hex_string: Optional[str]
    fourth_aadhaar_digit: str


@dataclass(frozen=True)
class Mobile(ContactMixin, ContactABC):
    hex_string: Optional[str]
    fourth_aadhaar_digit: str


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
    date_of_birth: date
    gender: Gender
    address: Address

    def to_dict(self) -> dict[str, Union[dict[str, str], str]]:
        extracted_text_data_dict = asdict(self)
        extracted_text_data_dict["reference_id"] = self.reference_id.to_dict()
        extracted_text_data_dict["date_of_birth"] = self.date_of_birth.isoformat()
        extracted_text_data_dict["gender"] = self.gender.value
        return extracted_text_data_dict


@dataclass(frozen=True)
class ContactData:
    email: Email
    mobile: Mobile

    def to_dict(self) -> dict[str, dict[str, Optional[str]]]:
        return {"email": self.email.to_dict(), "mobile": self.mobile.to_dict()}


@dataclass(frozen=True)
class ExtractedSecureQRData:
    text_data: ExtractedTextData
    image: Image.Image
    contact_info: ContactData

    def _img_to_base64(self) -> str:
        with BytesIO() as output:
            self.image.save(output, format="JPEG")
            image_data = output.getvalue()
        return "data:image/jpeg;base64," + b64encode(image_data).decode(
            _SECURE_QR_ENCODING,
        )

    def to_dict(self) -> dict:
        return {
            "text_data": self.text_data.to_dict(),
            "image": self._img_to_base64(),
            "contact_info": self.contact_info.to_dict(),
        }


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

    def decompress(self) -> bytes:
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
        return int(self._data[0 : self._data.find(255)].decode(_SECURE_QR_ENCODING))

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
        extracted_text_data = self._find_indexes_and_extract_text_data()
        return ExtractedTextData(
            name=extracted_text_data["name"],
            reference_id=self._make_reference_id(extracted_text_data["reference_id"]),
            gender=self._select_gender(extracted_text_data["gender"]),
            date_of_birth=datetime.strptime(
                extracted_text_data["dob"],
                "%d-%m-%Y",
            ).date(),
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

    def _find_indexes_and_extract_text_data(self) -> dict[str, str]:
        indexes = self._find_indexes_of_255_delimiters()
        return self._extract_text_data(indexes[1:])

    def _extract_text_data(self, indexes: list[int]) -> dict[str, str]:
        raw_extracted_data = {}
        previous = self._data.find(255) + 1
        for detail, index_position in zip(self._details, indexes):
            extracted_detail = self._data[previous:index_position].decode(
                _SECURE_QR_ENCODING,
            )
            raw_extracted_data[detail] = extracted_detail
            previous = index_position + 1
        return raw_extracted_data

    def _make_aadhaar_image(self) -> Image.Image:
        image_bytes = self._extract_aadhaar_image_data()
        img = Image.open(BytesIO(image_bytes))
        return self._convert_to_jpeg(img)

    def _extract_aadhaar_image_data(self) -> bytes:
        ending = len(self._data) - 256
        length_to_subtract = self._calculate_length_to_subtract()
        image_bytes = self._data[
            self._find_indexes_of_255_delimiters()[15] + 1 : ending - length_to_subtract
        ]
        return image_bytes

    @staticmethod
    def _convert_to_jpeg(img: Image.Image) -> Image.Image:
        with BytesIO() as output:
            img.save(output, format="JPEG")
            bytes_data = output.getvalue()
        return Image.open(BytesIO(bytes_data))

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

    def _make_contact_data(self) -> ContactData:
        extracted_text_data = self._find_indexes_and_extract_text_data()
        return ContactData(
            Email(self._extract_email_hash(), extracted_text_data["reference_id"][3]),
            Mobile(self._extract_mobile_hash(), extracted_text_data["reference_id"][3]),
        )

    def extract(self) -> ExtractedSecureQRData:
        return ExtractedSecureQRData(
            text_data=self._make_text_data(),
            image=self._make_aadhaar_image(),
            contact_info=self._make_contact_data(),
        )


def extract_data(data: int) -> ExtractedSecureQRData:
    scanned_integer = SecureQRCodeScannedInteger(data)
    integer_to_bytes = scanned_integer.convert_to_bytes()
    compressed_bytes = SecureQRCompressedBytesData(integer_to_bytes)
    decompressed_bytes = compressed_bytes.decompress()
    data_extractor = SecureQRDataExtractor(decompressed_bytes)
    return data_extractor.extract()
