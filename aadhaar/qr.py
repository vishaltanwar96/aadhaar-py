import zlib
from io import BytesIO
from base64 import b64encode
from typing import Union, Dict

from PIL import Image

from aadhaar.utils import generate_sha256_hexdigest
from aadhaar.exceptions import MalformedIntegerReceived


class AadhaarSecureQR:
    """
    Decodes information from a Secure Aadhaar QR Data
    """

    BYTEORDER = 'big'
    ENCODING_USED = 'ISO-8859-1'
    _details = [
        "email_mobile_number_bit",
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

    def __init__(self, integer_from_qr: Union[int, str]) -> None:

        if isinstance(integer_from_qr, str):
            try:
                integer_from_qr = int(integer_from_qr)
            except ValueError:
                raise TypeError('Passed string cannot be converted to an integer, please pass a valid integer')
        if not isinstance(integer_from_qr, int):
            raise TypeError('Expected integer value')

        self.integer_from_qr = integer_from_qr
        # Creating a byte sequence of 16 KB and removing null bytes(\x00) from the starting of the byte sequence

        self.byte_array = self.integer_from_qr.to_bytes(length=16*1024, byteorder=self.BYTEORDER).lstrip(b'\x00')

        # Keeping the window size to 16 + 15 -> 31 bits
        try:
            self.decompressed_byte_array = zlib.decompress(self.byte_array, wbits=16+zlib.MAX_WBITS)
        except zlib.error:
            raise MalformedIntegerReceived('Decompression failed, please send a valid integer received from QR code')

        self.decompressed_array_length = len(self.decompressed_byte_array)

        self.list_of_indexes_of_255_delimeter = [
            index
            for index in range(len(self.decompressed_byte_array))
            if self.decompressed_byte_array[index] == 255
        ]

        self._raw_extracted_data = {}

        previous = 0
        for detail, index_position in zip(self._details, self.list_of_indexes_of_255_delimeter):
            extracted_detail = self.decompressed_byte_array[previous:index_position].decode(self.ENCODING_USED)
            self._raw_extracted_data[detail] = extracted_detail
            previous = index_position + 1

    def is_mobile_present(self) -> bool:
        """
        from 0th index to the first 255 delimeter we get values from [0, 1, 2, 3] with following meaning
        0 -> email & mobile both are not available
        1 -> email is available but mobile isn't
        2 -> email isn't available but mobile is
        3 -> email and mobile both are available
        """

        return True if self._raw_extracted_data['email_mobile_number_bit'] in ('2', '3') else False

    def is_email_present(self) -> bool:
        """
        from 0th index to the first 255 delimeter we get values from [0, 1, 2, 3] with following meaning
        0 -> email & mobile both are not available
        1 -> email is available but mobile isn't
        2 -> email isn't available but mobile is
        3 -> email and mobile both are available
        """

        return True if self._raw_extracted_data['email_mobile_number_bit'] in ('1', '3') else False

    def get_signature(self) -> bytes:

        return self.decompressed_byte_array[self.decompressed_array_length-256:self.decompressed_array_length]

    def get_signed_data(self) -> bytes:

        return self.decompressed_byte_array[:self.decompressed_array_length-256]

    def get_mobile_sha256_hash(self) -> str:
        """returns sha256 hash value of the registered mobile number with aadhaar"""

        if self.is_mobile_present():
            return self.decompressed_byte_array[
                self.decompressed_array_length - 256 - 32: self.decompressed_array_length - 256
            ].hex()
        return ''

    def get_email_sha256_hash(self) -> str:
        """returns sha256 hash value of the email address registered with aadhaar"""

        if self.is_email_present():
            return self.decompressed_byte_array[
                self.decompressed_array_length - 256 - 32 - 32: self.decompressed_array_length - 256 - 32
            ].hex()
        return ''

    def get_image_data(self) -> str:
        """
        The compressed JPEG 2000 image is transformed into a base64 string for easy transportation (Rest APIs)
        """

        ending = self.decompressed_array_length - 256

        if self.is_mobile_present() and self.is_email_present():
            length_to_subtract = 32 * 2
        elif (self.is_mobile_present() and not self.is_email_present()) or (
            not self.is_mobile_present() and self.is_email_present()
        ):
            length_to_subtract = 32 * 1
        else:
            length_to_subtract = 32 * 0

        image_bytes = self.decompressed_byte_array[
            self.list_of_indexes_of_255_delimeter[15] + 1: ending - length_to_subtract
        ]

        img = Image.open(BytesIO(image_bytes))
        with BytesIO() as output:
            img.save(output, format='JPEG')
            image_data = output.getvalue()
        return b64encode(image_data).decode(self.ENCODING_USED)

    def validate_mobile_number(self, mobile_number: Union[str, int]) -> bool:
        """validates the input mobile number against the encoded mobile number embedded in the aadhaar qr code"""

        if not self.is_mobile_present():
            return False

        generated_hash = generate_sha256_hexdigest(
            str(mobile_number), int(self._raw_extracted_data['reference_id'][3])
        )
        return generated_hash == self.get_mobile_sha256_hash()

    def validate_email(self, email: str) -> bool:
        """validates the input email address against the encoded email address embedded in the aadhaar qr code"""

        if not self.is_email_present():
            return False

        generated_hash = generate_sha256_hexdigest(str(email), int(self._raw_extracted_data['reference_id'][3]))
        return generated_hash == self.get_email_sha256_hash()

    def extract_data(self) -> Dict[str, str]:
        """returns the extracted information from the qr code"""

        return {
            **self._raw_extracted_data,
            'photo': self.get_image_data(),
            'is_email_present': self.is_email_present(),
            'is_mobile_present': self.is_mobile_present(),
            'mobile_sha256_hash': self.get_mobile_sha256_hash(),
            'email_sha256_hash': self.get_email_sha256_hash(),
        }
