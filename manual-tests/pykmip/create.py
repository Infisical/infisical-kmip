import ssl

from kmip.pie.client import ProxyKmipClient, enums
from kmip.core.enums import CryptographicAlgorithm

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
   kmip_version=enums.KMIPVersion.KMIP_1_4
)

client.open()

client.create(
    CryptographicAlgorithm.AES,
    256,
)
