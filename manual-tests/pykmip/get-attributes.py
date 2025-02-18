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
   kmip_version=enums.KMIPVersion.KMIP_1_0
)

client.open()

attributes = client.get_attributes("97b81c55-56a3-4ac0-a99c-7cf60fe940be")
print(attributes)
