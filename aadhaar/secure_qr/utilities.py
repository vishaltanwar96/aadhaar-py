from hashlib import sha256

from aadhaar.secure_qr.exceptions import NumberOutOfRangeException


def generate_sha256_hexdigest(input_string: str, number_of_times: int) -> str:
    if number_of_times not in range(0, 10):
        raise NumberOutOfRangeException("Number can be in range 0-9")
    digest_string = input_string
    if number_of_times == 0:
        number_of_times = 1
    for _ in range(number_of_times):
        digest_string = sha256(digest_string.encode("ISO-8859-1")).hexdigest()
    return digest_string
