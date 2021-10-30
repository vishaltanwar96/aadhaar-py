import zlib


class MalformedDataReceived(Exception):
    pass


class SecureQRCodeScannedInteger:
    def __init__(self, data: int) -> None:
        self._data = data

    def convert_to_bytes(self) -> bytes:
        try:
            return self._data.to_bytes(byteorder="big", length=16 * 1024)
        except AttributeError:
            raise TypeError("Please send a valid integer value")

    def decompress(self):
        bytes_data = self.convert_to_bytes()
        bytes_data = bytes_data.lstrip(b"\x00")
        try:
            decompressed_data = zlib.decompress(bytes_data, wbits=zlib.MAX_WBITS + 15)
        except zlib.error:
            raise MalformedDataReceived(
                "Decompression failed, Please provide valid data.",
            )
        return decompressed_data
