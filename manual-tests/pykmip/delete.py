import ssl

from kmip.pie.client import ProxyKmipClient, enums

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

client.destroy("8b823975-b2ba-4f31-b5bc-0a9a1b5cb3d4")
