from enum import Enum


class Gender(Enum):
    MALE = "Male"
    FEMALE = "Female"
    TRANSGENDER = "Transgender"


class EmailMobileIndicator(Enum):
    EMAIL_MOBILE_BOTH_ABSENT = 0
    EMAIL_PRESENT_MOBILE_ABSENT = 1
    EMAIL_ABSENT_MOBILE_PRESENT = 2
    EMAIL_MOBILE_BOTH_PRESENT = 3
