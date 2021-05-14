import os
import zipfile
from unittest import TestCase
from tempfile import NamedTemporaryFile
from collections import OrderedDict

from aadhaar.qr import AadhaarSecureQR
from aadhaar.utils import generate_sha256_hexdigest
from aadhaar.exceptions import MalformedIntegerReceived, EmptyArchiveException, NoXMLFileFound
from aadhaar.offline_xml import AadhaarXMLOffline


class TestUtils(TestCase):

    def test_generate_sha256_hexdigest(self):

        test_hex_digest = 'd79ddb6ba12c0b0077571fadefe2cf3b875fc37a532ef6e084fcbef7e64e291a'
        self.assertEqual(generate_sha256_hexdigest('9999999999', 7), test_hex_digest)


class TestAadhaarSecureQR(TestCase):

    def setUp(self):

        self.sample_int = (
            "697941484820554848161929944287990190089397833259461440704476"
            "771748540728010407771465869816332540165921283092073423304757"
            "845470181056703201527022368291791582523470375471250488792130"
            "918178960780916888458384839645665300702247935633624019813036"
            "393088163236712473854151749949445813964737880868061416927322"
            "140474147659658395316924883137622439633516957706481298714057"
            "814488581947919017353764497023212514225396378497913801131879"
            "838544243609990162199828362481607008050483071259452576059693"
            "434157675562679159040363687813986166559938331942922836443418"
            "391319795873869700141049383928129869234282995156671253030975"
            "875936464970115363992197979842970756619926195003741817132928"
            "320737204801494866916066677619841404063338467710471769750752"
            "171758677670908420036495617886363610598886726092988757709295"
            "557040780378302139789734199991461679044102983722912974666922"
            "509563320109764432159350250340444071411051516703488912825896"
            "558343596503022584534856458205152134880074257444287708777419"
            "466898351662963107334120270545338278061377542733694928338808"
            "489165448422544694094166094244063778474429325991647984140708"
            "818946296448967023186648190423733849487281309889087584564003"
            "437037038710879895018022086543601275248721667704181731293011"
            "974760101780757756541397754569337548013132424069609987947943"
            "672257656644793959319559068459126180903802312217817200615049"
            "956918521883874933723828159703728892446400999753093833679817"
            "602359729232832096508699018453142618886296540831330897349592"
            "496514411339659382909064526665331377458203613898201336856147"
            "471915444713489446661156058975825182906322637030028217582347"
            "956984726143934840455825140227373086505348221458918002830204"
            "382143835758330281837414397399700274504752640575576040704500"
            "669442350133708178029981508032484033782881264430004190035681"
            "642911426109823019897675202600207987688279659723561501559448"
            "618205778147615291817074640315700521689623942852170603346606"
            "158760806503613315307443219595213136856423416800544777019034"
            "577702491762987963917116171992985207826530916075926098959061"
            "815888989183529473561436667450396158444549768573631262824848"
            "355198652986742301625547655369192205424168623096897522951170"
            "092817128154990268236530233367741295178883980686979604051223"
            "589931173433785868453115672141628011447336882646309848525239"
            "426007579038641587529092257056868643958603626246541400233411"
            "787008892280166052941475978431879984380613009699819088124040"
            "413886929330978233530529672066622024330417508635827821135578"
            "995799801480120933229345894046385910659198643452043381058356"
            "930922492926422826384147737894932931244395821593929443266946"
            "426021653407456088272300683845979281234025307833029113552695"
            "267520379083343023785283174060143319836424336356973020535107"
            "739344169114124005590081909122993160514686552018300181023970"
            "846432258838995603629176017555884381910541823458023961017432"
            "363660609526272294014370606369884649967328537762118057053778"
            "816030493680991523788948934238789105701278372669492018457320"
            "278967296392238002827112444802426564439668634150844783035138"
            "024212754239384941028383040959498850324679954444468760695488"
            "151059751568641099382890758897969914118016089306260333810485"
            "790323984585678313027593541356927543990878998331166321193744"
            "9259444259898972766208"
        )
        self.secure_qr = AadhaarSecureQR(self.sample_int)

    def test_b64encoded_image(self):

        image_b64_data = (
            '/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICI'
            'sIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMj'
            'IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAA8ADwDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAA'
            'AAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS'
            '0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4i'
            'JipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+P'
            'n6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExB'
            'hJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpj'
            'ZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1db'
            'X2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD1S/8AGdjb+HJdSjwZl+RYSeRIRwPp3z6A9+K8tn'
            '1G41q5e7uZW+Y5A9K53xLqkv2myhDMkbAkr75xWlBOFjRSygY7mpc7RLhC7uy8sUX3tgJ96iuAGH3Rj0phvIY+r'
            'p+BqJ76BhkNXM+Z6nZFLoU54VwcRgCmWX2V5GtruMPDKNpz2FOnvIyCAy49zVMSRysAkiBu3zVKTvc0k1azKUYn'
            '8F+J02qJrVyXj3k7ZIzzg47j+lem29888CTKqYcA5Hy598CuB8Qyef4ejjmT97bOGRu+OhFWtCvpp9Ih3yOfLGx'
            'ceg6V0x1RxSSuZ/iiCV5rGZxkCQRtjtk8Vl3s8jTMHlZQOFC1sXM8lxcRW8gIBw5PoQeKdcaXHNkKoDetQ5pM2h'
            'TfKckXm8whZpMr1BrbsIJry0crK64H3h1qc6G5d5XfryxHetfTLX7PZSbVABFRKqnsa06bT1OG1GSZpTGsjBvbv'
            'VO3A84oZnDjgmulu7CN5ww4eootIddwBBDnJzRGStqTODbFimnk0S7inkL+Ug2N7Z6V6T4N8Nvb+F7Q3SASygyE'
            'egJ4H5YriI7JbfTp0dcgr2+or2bwvfR6/oEF7HAsfWNowQdhU4x/I/QirTMZU3c8mvh5ZEi/eIH5c1FFenfk8+1'
            'XtTtnFsJeNo4rnCzeZhSR71lKOp005+6bU90fJYqg4GSKxk8RSlXQK0aduKZLqccAMZck96ovewN/yxmb6/8A6q'
            'IxKc30LttqKT5zH+8U4DY61feddue9c+t2kZYx5HPIIxj6VcgfzRuHNOUAU1bU2vOZtOlIGWA6fiK9N+Gen3Z8K'
            'NILh40kupCijpgYU/qDXnOkaVqGqxPFp1q1xICCwDqu3t1YgdeK900GwGm6FZWRVY2hhVGCdC2OT+eaaRlKep5Z'
            'PbLcQNC/3TXEX0MlnMYpAVkUHHoRXfD74rmvHahILN1GGywz/wB81c1qYU5PY5OJTuLrGCx7mkmW+PKrhRT7aRx'
            '0arTzyeWTuNRex2RWhkvGXH7xBuHer9kPKh5/DNQMS5yxyat6cxOp2kZPyGVcj8ad7mUl7x7T4A0SXSNH+0XSEX'
            'F185jdcFF7Ag9D1J+vtXXFzn09qr25LIrHqRk1NVIwm9T/2Q=='
        )
        self.assertEqual(self.secure_qr.get_image_data(), image_b64_data)

    def test_mobile_presence(self):

        original_bit = self.secure_qr._raw_extracted_data['email_mobile_number_bit']
        self.secure_qr._raw_extracted_data['email_mobile_number_bit'] = '0'
        self.assertFalse(self.secure_qr.is_mobile_present())
        self.secure_qr._raw_extracted_data['email_mobile_number_bit'] = '1'
        self.assertFalse(self.secure_qr.is_mobile_present())
        self.secure_qr._raw_extracted_data['email_mobile_number_bit'] = '2'
        self.assertTrue(self.secure_qr.is_mobile_present())
        self.secure_qr._raw_extracted_data['email_mobile_number_bit'] = '3'
        self.assertTrue(self.secure_qr.is_mobile_present())
        self.secure_qr._raw_extracted_data['email_mobile_number_bit'] = original_bit

    def test_email_presence(self):

        original_bit = self.secure_qr._raw_extracted_data['email_mobile_number_bit']
        self.secure_qr._raw_extracted_data['email_mobile_number_bit'] = '0'
        self.assertFalse(self.secure_qr.is_email_present())
        self.secure_qr._raw_extracted_data['email_mobile_number_bit'] = '1'
        self.assertTrue(self.secure_qr.is_email_present())
        self.secure_qr._raw_extracted_data['email_mobile_number_bit'] = '2'
        self.assertFalse(self.secure_qr.is_email_present())
        self.secure_qr._raw_extracted_data['email_mobile_number_bit'] = '3'
        self.assertTrue(self.secure_qr.is_email_present())
        self.secure_qr._raw_extracted_data['email_mobile_number_bit'] = original_bit


class TestExceptionsOnAadhaarSecureQR(TestCase):

    def test_raise_error_on_unaccepted_type(self):

        for type_ in [{'k': 'v'}, [123], 123.4123, 'abc']:
            with self.assertRaises(TypeError):
                AadhaarSecureQR(type_)

    def test_raise_error_on_integer_that_cant_be_decompressed(self):

        with self.assertRaises(MalformedIntegerReceived):
            AadhaarSecureQR(23123891283801283010283091820930910923809182038019280380128309)


class TestAadhaarOfflineXML(TestCase):

    def setUp(self):

        self.BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.RESOURCES_DIR = os.path.join(self.BASE_DIR, 'resources')
        self.zip_file_path = os.path.join(self.RESOURCES_DIR, 'test.zip')
        self.SHARE_CODE = 1234

    def test_working_aadhaar_offline_xml(self):

        xml_offline = AadhaarXMLOffline(self.zip_file_path, self.SHARE_CODE)
        decoded_aadhaar_data = xml_offline.extract_data()
        self.assertIn('OfflinePaperlessKyc', decoded_aadhaar_data)
        self.assertIn('referenceId', decoded_aadhaar_data['OfflinePaperlessKyc'])
        self.assertIn('UidData', decoded_aadhaar_data['OfflinePaperlessKyc'])
        self.assertIn('Poi', decoded_aadhaar_data['OfflinePaperlessKyc']['UidData'])
        self.assertIn('Poa', decoded_aadhaar_data['OfflinePaperlessKyc']['UidData'])
        self.assertIn('Pht', decoded_aadhaar_data['OfflinePaperlessKyc']['UidData'])
        self.assertIsInstance(decoded_aadhaar_data, OrderedDict)

    def test_not_zipfile(self):

        with NamedTemporaryFile(mode='w') as ntf:
            ntf.write('Sometext')
            with self.assertRaises(zipfile.BadZipfile):
                xml_offline = AadhaarXMLOffline(ntf.name, self.SHARE_CODE)
                xml_offline.extract_data()

    def test_empty_zipfile(self):

        file_name = 'empty.zip'
        with open(file_name, 'wb') as empty_zipfile:
            empty_zipfile.write(b'PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        with self.assertRaises(EmptyArchiveException):
            xml_offline = AadhaarXMLOffline(file_name, self.SHARE_CODE)
            xml_offline.extract_data()
        os.remove(file_name)

    def test_no_xml_zipfile(self):

        zipfile_name = 'no_xml.zip'
        with zipfile.ZipFile(zipfile_name, 'w') as zf:
            zf.writestr('test.txt', 'Sample Text Data')
        with self.assertRaises(NoXMLFileFound):
            xml_offline = AadhaarXMLOffline(zipfile_name, self.SHARE_CODE)
            xml_offline.extract_data()
        os.remove(zipfile_name)

    def test_invalid_sharecode(self):

        with self.assertRaises(RuntimeError):
            xml_offline = AadhaarXMLOffline(self.zip_file_path, 3456)
            xml_offline.extract_data()
