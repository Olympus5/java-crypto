# java-crypto

## OpenSSL

### OpenSSL information

#### Version information

```shell
# Add -a option to get a more verbose output
openssl version
```

#### Available algorithms

```shell
openssl help
```

#### Command help

```shell
openssl <command> -help
```

### Symmetric encryption

```shell
openssl enc -aes-256-cbc -in <file> -out <enc-file>
```

### Public and private keys

#### Generate keys

```shell
openssl genrsa -out key.pem 2048
```

#### Show key information

```shell
openssl rsa -in key.pem -text -noout
```

#### Extract public key

```shell
openssl rsa -in key.pem -pubout -out key.pub.pem
```

#### Encrypt key

```shell
openssl rsa -in key.pem -des3 -out enc-key.pem
```

#### Encrypt file with key

```shell
openssl pkeyutl -encrypt -in <file> -inkey key.pem -out <enc-file>
```

#### Encrypt file with public key

```shell
openssl pkeyutl -encrypt -in <file> -pubin -inkey key.pub.pem \
  -out <enc-file>
```

### File signature

#### Generate file hash/digest

Hash the file before any signature (performance issue)

```shell
# sha1 can be replaced with another accepted hash algorithm
openssl dgst -sha1 -out <digest> <file>
```

#### Sign file

```shell
openssl pkeyutl -sign -in <digest> -out <signature> -inkey <key.pem>
```

#### Verify file

```shell
openssl pkeyutl -verify -sigfile <signature> -in <digest> \
  -inkey <key.pem> -pubin
```

### Generate x509 CSR (Certificate Signature Request)

#### Generate CSR

```shell
# No key encryption with -nodes (no DES) option
openssl req -newkey rsa:2048 -keyout <cert-key> -out <cert-csr>
```

#### Generate CSR with a given key

```shell
openssl req -key <cert-key> -new -out <cert-csr>
```

#### Generate CSR from a given certificate and key

```shell
openssl x509 -in <cert-cer> -signkey <cert-key> \
  -x509toreq -out <cert-csr>
```

### Generate self-signed x509 certificate

#### Generate certificate

```shell
openssl req -newkey rsa:2048 -nodes -keyout <cert-key> -x509 \
  -days 365 -out <cert-cer>
```

#### Generate certificate with a given key

```shell
openssl req -key <cert-key> -new -x509 -days 365 -out <cert-cer>
```

### Show certificate

#### Show CSR

```shell
openssl req -text -noout -verify -in <cert-csr>
```

#### Show certificate

```shell
openssl x509 -text -noout -in <cert-cer>
```

#### Verify certificate signature

```shell
openssl verify -verbose -CAfile <cert-ca> <cert-cer>
```