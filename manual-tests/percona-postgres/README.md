## References

https://docs.percona.com/postgresql/17/docker.html#enable-encryption

https://docs.percona.com/pg-tde/setup.html

## Step by step

CREATE EXTENSION pg_tde;

SELECT pg_tde_add_key_provider_kmip('infisical-kmip-final','host.docker.internal', 5696, '/etc/pg/certs/client-chain.pem', '/etc/pg/certs/client-cert.pem');

SELECT pg_tde_set_principal_key('infisical-key', 'infisical-kmip-final');

CREATE TABLE albums (
album_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
artist_id INTEGER,
title TEXT NOT NULL,
released DATE NOT NULL
) USING tde_heap;
INSERT INTO albums(artist_id, title, released) VALUES (1, 'The dane', '03-07-2003');

SELECT \* FROM albums;

SELECT pg_tde_is_encrypted('albums');

## Notes

- Client certificate file must contain certificate (PEM format) and private key (PKCS#8 format)
