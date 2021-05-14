import os
import zipfile
from typing import Union
from operator import getitem
from functools import reduce
from collections import OrderedDict

import xmltodict

from aadhaar.utils import generate_sha256_hexdigest
from aadhaar.exceptions import EmptyArchiveException, NoXMLFileFound


class AadhaarXMLOffline:

    def __init__(self, path_to_aadhaar_zipfile: str, share_code: Union[str, int]) -> None:

        if not os.path.exists(path_to_aadhaar_zipfile):
            raise IOError("File doesn't exist")
        self.path_to_aadhaar_zipfile = path_to_aadhaar_zipfile
        self.share_code = str(share_code)

    def extract_data(self) -> OrderedDict:

        with zipfile.ZipFile(self.path_to_aadhaar_zipfile) as xml_zipfile:
            list_of_files = xml_zipfile.namelist()
            if not list_of_files:
                raise EmptyArchiveException('No files detected in the passed zip file')
            if not list_of_files[0].endswith('.xml'):
                raise NoXMLFileFound('No XML files found in the passed zip file')
            xml_file_name = list_of_files[0]
            with xml_zipfile.open(xml_file_name, pwd=str(self.share_code).encode()) as xml_file:
                xml_data = xml_file.read().decode()
        return xmltodict.parse(xml_data, attr_prefix='')

    def extract_reference_id(self) -> str:

        return self.extract_data()['OfflinePaperlessKyc']['referenceId']

    def validate_email(self, email: str) -> bool:

        traversal_list = ['OfflinePaperlessKyc', 'UidData', 'Poi', 'e']
        data = self.extract_data()
        email_hash = reduce(getitem, traversal_list, data)
        return email_hash == generate_sha256_hexdigest(str(email)+self.share_code, int(self.extract_reference_id()[3]))

    def validate_mobile_number(self, mobile_number: Union[str, int]) -> bool:

        traversal_list = ['OfflinePaperlessKyc', 'UidData', 'Poi', 'm']
        data = self.extract_data()
        email_hash = reduce(getitem, traversal_list, data)
        return email_hash == generate_sha256_hexdigest(
            str(mobile_number)+self.share_code,
            int(self.extract_reference_id()[3])
        )
