class SecureQRCodeCompressedBytesData:
    def __init__(self, scanned_integer_data: int) -> None:
        self._scanned_integer_data = scanned_integer_data

    def compress(self) -> bytes:
        return self._scanned_integer_data.to_bytes(length=16 * 1_024, byteorder="big")
