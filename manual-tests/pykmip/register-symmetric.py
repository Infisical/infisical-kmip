from kmip.pie.client import ProxyKmipClient, enums
from kmip.pie import objects

client = ProxyKmipClient(
   hostname='localhost',
   port=5696,
   cert='./certificates/client-cert.pem',
   key='./certificates/client-private-key.txt',
   ca='./certificates/client-chain.pem',
   ssl_version="PROTOCOL_SSLv23",
   username='',
   password='',
   config='client',
   config_file='./pykmip.conf',
   kmip_version=enums.KMIPVersion.KMIP_1_0
)

client.open()

symmetric_key = objects.SymmetricKey(
   enums.CryptographicAlgorithm.AES,
   128,
   (
       b'\x00\x01\x02\x03\x04\x05\x06\x07'
       b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
   )
 )

client.register(
    symmetric_key
)
