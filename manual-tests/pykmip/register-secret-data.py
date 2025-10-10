from kmip.pie.client import ProxyKmipClient, enums
from kmip.pie import objects

client = ProxyKmipClient(
   hostname='127.0.0.1',
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

# Simulating PowerScale OneFS sending symmetric key as SecretData
# OneFS typically sends encryption keys as SecretData to external key managers
symmetric_key_bytes = (
    b'\x00\x01\x02\x03\x04\x05\x06\x07'
    b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
    b'\x10\x11\x12\x13\x14\x15\x16\x17'
    b'\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F'
)

secret_data = objects.SecretData(
    symmetric_key_bytes,
    enums.SecretDataType.PASSWORD  # Using PASSWORD as it's a common available type
)

client.register(
    secret_data
)
