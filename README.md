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


## License

The license is the GPLv3+, see [COPYING](COPYING).

Please note, that if you use this applet in commercial products, the GPLv3
demands that the user can modify the source code *and* replace the applet on the
smart card. Therefore, you probably have to supply the user with the security
key of the smart card.
