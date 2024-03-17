// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.KeyAgreement;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class NeoKeyStore {
	public static final byte SHA1 = 0;
	public static final byte SHA224 = 1;
	public static final byte SHA256 = 2;
	public static final byte SHA384 = 3;
	public static final byte SHA512 = 4;

	private short algorithmAttributesTag;
	private NeoKey[] keyStore;
	byte keyRef;

	/* needed by RSA keys */
	private Cipher signatureCipher;
	private Cipher decryptionCipher;
	private Cipher authenticationCipher;

	/* needed by ECDSA keys */
	private Signature[] signatureSignatures;
	private KeyAgreement decryptionKeyAgreement;
	private Signature[] authenticationSignatures;

	public NeoKeyStore(byte keyRef, short bitmask) {
		short n = 0;

		bitmask &= 0x03f9;

		for (short i = (short)1; (i & (short)0x3ff) != 0; i <<= 1)
			if ((bitmask & i) == i)
				n++;

		/* At least one key is needed */
		if (n == 0)
			ISOException.throwIt(ISO7816.SW_UNKNOWN);
		this.keyRef = keyRef;
		keyStore = new NeoKey[n];

		n = 0;
		if ((bitmask & (short)0x0001) == (short)0x0001)
			addRSAKey(n++, new NeoRSAKey(keyRef, (short)2048));
		if ((bitmask & (short)0x0002) == (short)0x0002)
			addRSAKey(n++, new NeoRSAKey(keyRef, (short)3072));
		if ((bitmask & (short)0x0004) == (short)0x0004)
			addRSAKey(n++, new NeoRSAKey(keyRef, (short)4096));
		if ((bitmask & (short)0x0008) == (short)0x0008)
			addECKey(n++, new NeoSECP256R1Key(keyRef));
		if ((bitmask & (short)0x0010) == (short)0x0010)
			addECKey(n++, new NeoSECP384R1Key(keyRef));
		if ((bitmask & (short)0x0020) == (short)0x0020)
			addECKey(n++, new NeoSECP521R1Key(keyRef));
		if ((bitmask & (short)0x0040) == (short)0x0040)
			addECKey(n++, new NeoBrainpoolP256R1Key(keyRef));
		if ((bitmask & (short)0x0080) == (short)0x0080)
			addECKey(n++, new NeoBrainpoolP384R1Key(keyRef));
		if ((bitmask & (short)0x0100) == (short)0x0100)
			addECKey(n++, new NeoBrainpoolP512R1Key(keyRef));
		if ((bitmask & (short)0x0200) == (short)0x0200)
			addECKey(n++, new NeoSECP256K1Key(keyRef));

		switch (keyRef) {
		case NeoKey.SIGNATURE_KEY:
			algorithmAttributesTag = NeoPGPApplet.TAG_ALGORITHM_ATTRIBUTES_SIGNATURE;
			break;
		case NeoKey.DECRYPTION_KEY:
			algorithmAttributesTag = NeoPGPApplet.TAG_ALGORITHM_ATTRIBUTES_DECRYPTION;
			break;
		case NeoKey.AUTHENTICATION_KEY:
			algorithmAttributesTag = NeoPGPApplet.TAG_ALGORITHM_ATTRIBUTES_AUTHENTICATION;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_UNKNOWN);
		}

	}

	private void addRSAKey(short n, NeoRSAKey key) {
		switch (keyRef) {
		case NeoKey.SIGNATURE_KEY:
			if (signatureCipher == null)
				signatureCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
			key.init(signatureCipher, Cipher.MODE_ENCRYPT);
			break;
		case NeoKey.DECRYPTION_KEY:
			if (decryptionCipher == null)
				decryptionCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
			key.init(decryptionCipher, Cipher.MODE_DECRYPT);
			break;
		case NeoKey.AUTHENTICATION_KEY:
			if (authenticationCipher == null)
				authenticationCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
			key.init(authenticationCipher, Cipher.MODE_ENCRYPT);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_UNKNOWN);
			break;
		}

		keyStore[n] = key;
	}

	private Signature[] createSignatures() {
		Signature[] signatures = new Signature[5];

		signatures[SHA1] = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
		signatures[SHA224] = Signature.getInstance(Signature.ALG_ECDSA_SHA_224, false);
		signatures[SHA256] = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
		signatures[SHA384] = Signature.getInstance(Signature.ALG_ECDSA_SHA_384, false);
		signatures[SHA512] = Signature.getInstance(Signature.ALG_ECDSA_SHA_512, false);

		return signatures;
	}

	private void addECKey(short n, NeoECKey key) {
		switch (keyRef) {
		case NeoKey.SIGNATURE_KEY:
			if (signatureSignatures == null)
				signatureSignatures = createSignatures();
			key.init(signatureSignatures);
			break;
		case NeoKey.DECRYPTION_KEY:
			if (decryptionKeyAgreement == null)
				decryptionKeyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
			key.init(decryptionKeyAgreement);
			break;
		case NeoKey.AUTHENTICATION_KEY:
			if (authenticationSignatures == null)
				authenticationSignatures = createSignatures();
			key.init(authenticationSignatures);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_UNKNOWN);
			break;
		}

		keyStore[n] = key;
	}

	public NeoKey getDefaultKey() {
		return keyStore[0];
	}

	public void clear() {
		for (short i = 0; i < keyStore.length; i++)
			keyStore[i].clear();
	}

	public short getImportBufferSize() {
		short size = 0;
		short tmp;

		for (short i = 0; i < keyStore.length; i++) {
			tmp = keyStore[i].getImportBufferSize();
			if (size < tmp)
				size = tmp;
		}

		return size;
	}

	public short getAllAlgorithmAttributes(byte[] buf, short off) {
		short lengthOffset;

		for (short i = 0; i < keyStore.length; i++) {
			off = NeoPGPApplet.setTag(buf, off, algorithmAttributesTag);
			off = lengthOffset = NeoPGPApplet.prepareLength1(buf, off);
			off = keyStore[i].getAlgorithmAttributes(buf, off);
			NeoPGPApplet.setPreparedLength1(buf, off, lengthOffset);
		}

		return off;
	}

	public NeoKey setAlgorithmAttributes(byte[] buf, short off, short len) {
		for (short i = 0; i < keyStore.length; i++) {
			NeoKey key = keyStore[i];

			key.clear();
			if (key.matchAlgorithmAttributes(buf, off, len))
				return key;
		}
		ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		return null;
	}
}
