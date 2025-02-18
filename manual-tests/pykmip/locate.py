from kmip.pie.client import ProxyKmipClient, enums
from kmip.core.factories import attributes

f = attributes.AttributeFactory()

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
locs = client.locate(offset_items=0, maximum_items=2, attributes=[
         f.create_attribute(
             enums.AttributeType.STATE,
             enums.State.ACTIVE,
         ),
        f.create_attribute(
             enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
             256,
         )
     ])

print(locs)
