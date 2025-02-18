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

object = client.get("e758de61-96ee-4b8a-bb26-6f64e52c67be")
print(object.cryptographic_algorithm)
print(object.cryptographic_length)
print(object.cryptographic_usage_masks)

object = client.get("e758de61-96ee-4b8a-bb26-6f64e52c67be", {
          'wrapping_method': enums.WrappingMethod.ENCRYPT,
          'encryption_key_information': {
              'unique_identifier': "97b81c55-56a3-4ac0-a99c-7cf60fe940be",
              'cryptographic_parameters': {
                  'block_cipher_mode':
                      enums.BlockCipherMode.NIST_KEY_WRAP
              }
          },
          'encoding_option': enums.EncodingOption.NO_ENCODING
      })

print(object.cryptographic_algorithm)
print(object.cryptographic_length)
print(object.cryptographic_usage_masks)
