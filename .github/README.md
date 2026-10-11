# Sipri Crypto

**Sipri Crypto** is a Java cryptography library based on [Bouncy Castle Crypto for Java](https://github.com/bcgit/bc-java), adding the Korean national algorithms Bouncy Castle lacks: KCDSA, EC-KCDSA, LSH, HIGHT and HAS-160, together with a `SipriCrypto` JCA/JCE provider.

The Bouncy Castle sources are tracked unmodified. Everything Sipri-specific lives in the [`sipri/`](../sipri) module (package `com.siprikorea.crypto`), so each Bouncy Castle release merges in without conflicts. See [`SIPRI.md`](../SIPRI.md) for the repository layout and the upstream sync process.

## Supported algorithms

| Category | Algorithm | Standard | Provided by |
|---|---|---|---|
| Signature | KCDSA (SHA-224, SHA-256, legacy HAS-160) | TTAK.KO-12.0001/R4, ISO/IEC 14888-3 | **SipriCrypto** |
| Signature | EC-KCDSA (SHA-224/256/384/512) | TTAK.KO-12.0015/R3, ISO/IEC 14888-3 | **SipriCrypto** |
| Hash | LSH-224/256, LSH-384/512, LSH-512-224/256 | KS X 3262 | **SipriCrypto** |
| Hash | HAS-160 (legacy) | TTAS.KO-12.0011/R2 | **SipriCrypto** |
| Block cipher | HIGHT (64-bit block, 128-bit key) | TTAS.KO-12.0040/R1, ISO/IEC 18033-3 | **SipriCrypto** |
| Block cipher | SEED, ARIA, LEA | RFC 4269 / RFC 5794 / KS X 3246 | Bouncy Castle (`BC`) |

SEED, ARIA and LEA are already part of the Bouncy Castle `BC` provider; register both providers to cover the full set of Korean algorithms.

## Usage

```java
Security.addProvider(new BouncyCastleProvider());   // SEED, ARIA, LEA, ...
Security.addProvider(new SipriCryptoProvider());    // KCDSA, EC-KCDSA, LSH, HIGHT, HAS-160

// EC-KCDSA signature
KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECKCDSA", "SipriCrypto");
kpg.initialize(new ECGenParameterSpec("secp256r1"));
KeyPair kp = kpg.generateKeyPair();

Signature sig = Signature.getInstance("SHA256withECKCDSA", "SipriCrypto");
sig.initSign(kp.getPrivate());
sig.update(message);
byte[] signature = sig.sign();

// LSH hash
byte[] digest = MessageDigest.getInstance("LSH-256", "SipriCrypto").digest(message);

// HIGHT encryption
Cipher cipher = Cipher.getInstance("HIGHT/CBC/PKCS5Padding", "SipriCrypto");
```

The lightweight API (`com.siprikorea.crypto.signers.KCDSASigner`, `ECKCDSASigner`, `digests.LSH256Digest`, `engines.HIGHTEngine`, ...) can be used without the JCA, in the same way as the Bouncy Castle lightweight API.

## Building

Gradle must run on JDK 25 (a Bouncy Castle build requirement).

```
./gradlew :prov:compileJava :sipri:build     # build and test the Sipri module
```

The artifact is `sipri/build/libs/sipri-crypto-jdk18on-<version>.jar`, with Maven coordinates `com.siprikorea.crypto:sipri-crypto-jdk18on`; it needs `bcprov-jdk18on` at runtime.

## License

MIT, the same license as Bouncy Castle ([`LICENSE.md`](../LICENSE.md)). The Bouncy Castle parts of this source tree are *Copyright (c) 2000-2026 The Legion of the Bouncy Castle Inc.* Sipri Crypto is an independent distribution and is not affiliated with the Bouncy Castle project.

The original Bouncy Castle README is [`README.md`](../README.md) at the repository root.
