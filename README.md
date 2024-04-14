# NeoPGP - A robust Java Card OpenPGP applet

## Prior Work
* [SmartPGP](https://github.com/github-af/SmartPGP)
* [YubiKey NEO OpenPGP](https://github.com/Yubico/ykneo-openpgp)
* [JavaCardOS OpenPGPApplet](https://github.com/JavaCardOS/OpenPGPApplet)
* [OpenPGPo-Card](https://github.com/FluffyKaon/OpenPGP-Card)


## So, why yet another OpenPGP applet?

Only SmartPGP supports ECC keys, all the other applets only support RSA keys.
SmartPGP on the other hand use dynamically allocated memory. On a Java Card,
all objects are allocated in non-volatile memory, not in RAM. While the API
offers a manual garbage colletion via `JCSystem.requestObjectDeletion()`, this
is (a) optional and (b) apparently broken on some cards[^1]. Thus it is not
possible to return any allocations to the OS. If the applet will drop a
reference to an object this memory is leaked forever. It is good practice to
only allocate memory during the applet installation, that is preallocate any
object which will ever be used by the applet. This is exactly what NeoPGP is
doing. There are no uses of the new operator (or calls to factory functions)
outside of an object constructor and all objects are created during the
`.install()` hook.

[^1]: https://stackoverflow.com/questions/28147582/ implies that the garbage
    collention might brick the whole card and should only be used in secure
    environment, i.e. during card production.


## Features

- [x] Pre-allocated resources
- [x] Resources consumption configurable during applet registration
- [x] Generate keys on card
- [x] Key algorithm changable
- [x] Key import
- [x] Support for RSA keys
- [x] Support for ECC keys
- [x] KDF support
- [x] Get Challenge command support
- [ ] AES encryption/decryption
- [ ] Per signature request PIN verification
- [ ] Private DOs
- [ ] SmartPGPs secure messaging

## Build it yourself

You have to download a java card development kit, either from the [offical
source](https://www.oracle.com/java/technologies/javacard-downloads.html) or
by cloning the handy [git
repository](https://github.com/martinpaljak/oracle_javacard_sdks). Set the
environment variable `JC_HOME` to the SDK you want to use.

The latest SDK v3.1 will support newer java compiler and still can generate
code for the 3.0.x java cards.

```
export JC_HOME=/path/to/jcsdk
ant
```

If everything is successful, there will be a `NeoPGPApplet.cap`.


## Installation

You can use
[GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) to
install the `NeoPGPApplet.cap` onto your smart card. E.g.

```
java gp.jar -install NeoPGPApplet.cap
```

### Configuration Parameters

NeoPGP is highly configurable. During applet installation you can choose the
supported key and quirks that are needed for your card, can be enabled.

| Parameter Bitmask | Description             |
| ----------------- | ----------------------- |
|        `00010000` | RSA-2048 support        |
|        `00020000` | RSA-3072 support        |
|        `00040000` | RSA-4096 support        |
|        `00080000` | NIST P-256 support      |
|        `00100000` | NIST P-384 support      |
|        `00200000` | NIST P-521 support      |
|        `00400000` | Brainpool P-256 support |
|        `00800000` | Brainpool P-384 support |
|        `01000000` | Brainpool P-512 support |
|        `02000000` | secp256k1 support       |
|        `00000001` | Disable transaction during key generation |
|        `00000002` | Turn on KDF by default |
|        `00000004` | Disable tag and length field for GET DATA on the KDF DO |

### Working Cards

| Java Card               | Parameters | Notes |
| ----------------------- | ---------- | ----- |
| JCOP J3R180 (DI)        | `03f90000` | [1]   |
| JCOP J3R180 4K RSA (DI) | `03ff0000` | [1]   |
| ACOSJ 40K (DI)          | `00d80001` | [2], [3] |

- [1]: 3k/4k-RSA needs special pre-personalization and is not always available.
- [2]: Only ECC, because no ExtendedLength support.
- [3]: ECC up to 384bits.

## License

The license is the GPLv3+, see [COPYING](COPYING).

Please note, that if you use this applet in commercial products, the GPLv3
demands that the user can modify the source code *and* replace the applet on the
smart card. Therefore, you probably have to supply the user with the security
key of the smart card.
