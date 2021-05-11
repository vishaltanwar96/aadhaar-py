from hashlib import sha256

from src.exceptions import NumberOutOfRangeException


def generate_sha256_hexdigest(input_string: str, number_of_times: int) -> str:
    """
    Generate hex digest for n number of times if the number is between 2-9 else just once
    """
    if number_of_times not in range(0, 10):
        raise NumberOutOfRangeException('Number can be in range 0-9')

    if number_of_times == 0:
        number_of_times = 1
    for _ in range(number_of_times):
        input_string = sha256(input_string.encode()).hexdigest()
    return input_string
