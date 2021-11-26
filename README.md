# aadhaar-py
This library helps you extract the embedded information in Aadhaar Secure QR Code

# Inspired from
I would like to thank the authors of [pyaadhaar](https://github.com/Tanmoy741127/pyaadhaar). It wouldn't be possible to move into the right direction without this library.

# Demo
[Secure Aadhaar QR Decoder](https://aadhaar-secure-qr.herokuapp.com/)

# Enough talk, show me how it works!
```python-repl
>>> from aadhaar.secure_qr import extract_data
>>> received_qr_code_data = 12345678
>>> extracted_data = extract_data(received_qr_code_data)
```

The extract_data returns an instance of ExtractedSecureQRData which has the definition of:
```python
@dataclass(frozen=True)
class ExtractedSecureQRData:
    text_data: ExtractedTextData
    image: Image.Image
    contact_info: ContactData
```


Text Data:
```python-repl
>>> extracted_data.text_data
ExtractedSecureQRData(text_data=ExtractedTextData(reference_id=ReferenceId(last_four_aadhaar_digits='8908', timestamp=datetime.datetime(2019, 3, 5, 15, 1, 37, 123000)), name='Penumarthi Venkat', date_of_birth=datetime.datetime(1987, 5, 7, 0, 0), gender=<Gender.MALE: 'Male'>, address=Address(care_of='S/O: Pattabhi Rama Rao', district='East Godavari', landmark='Near Siva Temple', house='4-83', location='Sctor-2', pin_code='533016', post_office='Aratlakatta', state='Andhra Pradesh', street='Main Road', sub_district='Karapa', vtc='Aratlakatta')), image=<PIL.JpegImagePlugin.JpegImageFile image mode=RGB size=60x60 at 0x1095B9280>, contact_info=ContactData(email=Email(hex_string=None, fourth_aadhaar_digit='8'), mobile=Mobile(hex_string='1f31f19afc2bacbd8afb84526ae4da184a2727e8c2b1b6b9a81e4dc6b74d692a', fourth_aadhaar_digit='8')))
```

The Embedded Image:
```python-repl
>>> extracted_data.image
<PIL.JpegImagePlugin.JpegImageFile image mode=RGB size=60x60 at 0x1029CA460>
```

The Contact Information:
```python-repl
>>> extracted_data.contact_info
ContactData(email=Email(hex_string=None, fourth_aadhaar_digit='8'), mobile=Mobile(hex_string='1f31f19afc2bacbd8afb84526ae4da184a2727e8c2b1b6b9a81e4dc6b74d692a', fourth_aadhaar_digit='8'))
```

But hey, I want to send this data via a ReSTful API, how can I do that? `to_dict` method to the rescue!
```python-repl
>>> extracted_data.to_dict()
{
  "text_data": {
    "reference_id": {
      "last_four_aadhaar_digits": "8908",
      "timestamp": "2019-03-05T15:01:37.123000"
    },
    "name": "Penumarthi Venkat",
    "date_of_birth": "1987-05-07",
    "gender": "Male",
    "address": {
      "care_of": "S/O: Pattabhi Rama Rao",
      "district": "East Godavari",
      "landmark": "Near Siva Temple",
      "house": "4-83",
      "location": "Sctor-2",
      "pin_code": "533016",
      "post_office": "Aratlakatta",
      "state": "Andhra Pradesh",
      "street": "Main Road",
      "sub_district": "Karapa",
      "vtc": "Aratlakatta"
    }
  },
  "image": "data:image/jpeg;base64,/9j/4AAQSkZblahblah",
  "contact_info": {
    "email": {
      "hex_string": None
    },
    "mobile": {
      "hex_string": "1f31f19afc2bacbd8afb84526ae4da184a2727e8c2b1b6b9a81e4dc6b74d692a"
    }
  }
}

```

# Run Tests
```bash
python -m unittest discover tests/ --verbose
```
