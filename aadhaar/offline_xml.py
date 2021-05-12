import zipfile
from typing import Union, BinaryIO
from collections import OrderedDict

import xmltodict

from aadhaar.exceptions import EmptyArchiveException, NoXMLFileFound


def decode_offline_xml(path_to_aadhaar_zipfile: Union[str, BinaryIO], share_code: Union[str, int]) -> OrderedDict:

    with zipfile.ZipFile(path_to_aadhaar_zipfile) as xml_zipfile:
        list_of_files = xml_zipfile.namelist()
        if not list_of_files:
            raise EmptyArchiveException('No files detected in the passed zip file')
        if not list_of_files[0].endswith('.xml'):
            raise NoXMLFileFound('No XML files found in the passed zip file')
        xml_file_name = list_of_files[0]
        with xml_zipfile.open(xml_file_name, pwd=str(share_code).encode()) as xml_file:
            xml_data = xml_file.read().decode()
    return xmltodict.parse(xml_data, attr_prefix='')
