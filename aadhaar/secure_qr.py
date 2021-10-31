import zlib


class MalformedDataReceived(Exception):
    pass


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
    def __init__(self) -> None:
        pass
