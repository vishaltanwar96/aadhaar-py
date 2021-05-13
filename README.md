# aadhaar-py
This library aims to decode the extracted information from Aadhaar Secure QR Code along with decoding the data in Aadhar Offline XML.

# Inspired from
I would like to thank the authors of [pyaadhaar](https://github.com/Tanmoy741127/pyaadhaar). It wouldn't be possible to move into the right direction without this library.

# So why should you use aadhar-py?
1. Refactored Code
2. Tests
3. Images are extracted in Base64 format
4. Easy to read variable names
5. Documentation using docstrings
6. Type Hints
7. Better exception handling

# Enough talk, show me how it works!

Aadhaar Secure QR:
```python
>>> from aadhaar.qr import AadhaarSecureQR
>>> integer_scanned_from_qr = 123456
>>> secure_qr = AadhaarSecureQR(integer_scanned_from_qr)
>>> secure_qr.extract_data()
{
    'email_mobile_number_bit': '2',
    'reference_id': '890820190305150137123',
    'name': 'Penumarthi Venkat',
    'dob': '07-05-1987',
    'gender': 'M',
    'care_of': 'S/O: Pattabhi Rama Rao',
    'district': 'East Godavari',
    'landmark': 'Near Siva Temple',
    'house': '4-83',
    'location': 'Sctor-2',
    'pincode': '533016',
    'post_office': 'Aratlakatta',
    'state': 'Andhra Pradesh',
    'street': 'Main Road',
    'sub_district': 'Karapa',
    'vtc': 'Aratlakatta',
    'photo': 'base64_image_string',
    'is_email_present': False,
    'is_mobile_present': True
}

# Validate mobile number and email using
>>> secure_qr.validate_mobile_number('9999999999')
True
>>> secure_qr.validate_email('someuser@domain.com')
False
```

Aadhaar Offline XML:

```python
>>> from aadhaar.offline_xml import AadhaarXMLOffline
>>> xml_offline = AadhaarXMLOffline('path_to_aadhaar.zip', 'MyShareCode@123')
>>> xml_offline.extract_data()
# decode_offline_xml returns an OrderedDict
# but for readability this is changed to dict
{
  "OfflinePaperlessKyc": {
    "referenceId": "394120210203170827385",
    "UidData": {
      "Poi": {
        "dob": "10-02-1999",
        "e": "",
        "gender": "M",
        "m": "73722be8e5670b60c72525f7225adcd0673e5cd208cc7cb2f97b4d9069b88d1d",
        "name": "Hardeep Kalra"
      },
      "Poa": {
        "careof": "S/O Sukhdeep Kalra",
        "country": "India",
        "dist": "Rupnagar",
        "house": "B-1123/178",
        "landmark": "",
        "loc": "Mohalla Sheikhan",
        "pc": "140021",
        "po": "Ropar",
        "state": "Punjab",
        "street": "",
        "subdist": "",
        "vtc": "Rupnagar"
      },
      "Pht": "base64_image_data"
    },
    "Signature": {
      "xmlns": "http://www.w3.org/2000/09/xmldsig#",
      "SignedInfo": {
        "CanonicalizationMethod": {
          "Algorithm": "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        },
        "SignatureMethod": {
          "Algorithm": "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
        },
        "Reference": {
          "URI": "",
          "Transforms": {
            "Transform": {
              "Algorithm": "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
            }
          },
          "DigestMethod": {
            "Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"
          },
          "DigestValue": "4l0XaVXj65ZfPKCqqbo7RzIFuJAql88w8fqiHAHhxXs="
        }
      },
      "SignatureValue": "ihKm5WYnEVg5CvoAs49bd3oUDecd8vPd/721/ARUOXRcsJE2nzM40aw/6pHkoaEnK+/fXwVQSWnX\\nY3vdzaJcuJepndG8bJITOQ1s8nybZKfQUSLE/w5qz47JdhlYyKvC6K3Vxn+y19BF4W7z9lH9hX/J\\n2kd9ORoLSG232bctVKICtUJLmoRKwgjL0HmKXdSAP5faCOA+BsMOD5ieIvWwnM+CAhOr9NXJNML6\\nvXnGMNzlYSbgDs1FPblWclAur+ty2I99Of6G3ewE5OSJggUYpv/zoYY/Mq1/toZOea85QYokOJOY\\nlYJ8vgnrBC6qG1WtU10Q1zhrpcHrQhdWi5vNiQ=="
    }
  }
}

# Validate mobile number and email using
>>> xml_offline.validate_mobile_number('999999999')
True
>>> xml_offline.validate_email('someuser@domain.com')
False
```

# Run Tests
```bash
python -m unittest aadhaar/tests.py
```
