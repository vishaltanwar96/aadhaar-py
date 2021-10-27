class SecureQRCodeScannedInteger:
    def __init__(self, data: int) -> None:
        self._data = data

    def convert_to_bytes(self) -> bytes:
        return self._data.to_bytes(byteorder="big", length=16 * 1024)


class SecureQRCompressedBytesData:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def decompress(self):
        pass
