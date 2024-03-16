// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacardx.crypto.Cipher;

public class NeoKeyStore {
	private short algorithmAttributesTag;
	private NeoKey[] keyStore;

	/* needed by RSA keys */
	Cipher signatureCipher;
	Cipher decryptionCipher;
	Cipher authenticationCipher;

	public NeoKeyStore(byte keyRef, short bitmask) {
		short n = 0;

		bitmask &= 0x0007;
		for (short i = (short)1; (i & (short)0x3ff) != 0; i <<= 1)
			if ((bitmask & i) == i)
				n++;

		/* At least one key is needed */
		if (n == 0)
			ISOException.throwIt(ISO7816.SW_UNKNOWN);
		keyStore = new NeoKey[n];

		n = 0;
		if ((bitmask & (short)0x0001) == (short)0x0001)
			addRSAKey(n++, new NeoRSAKey(keyRef, (short)2048));
		if ((bitmask & (short)0x0002) == (short)0x0002)
			addRSAKey(n++, new NeoRSAKey(keyRef, (short)3072));
		if ((bitmask & (short)0x0004) == (short)0x0004)
			addRSAKey(n++, new NeoRSAKey(keyRef, (short)4096));

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
		switch (algorithmAttributesTag) {
		case NeoPGPApplet.TAG_ALGORITHM_ATTRIBUTES_SIGNATURE:
			if (signatureCipher == null)
				signatureCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
			key.init(signatureCipher, Cipher.MODE_ENCRYPT);
			break;
		case NeoPGPApplet.TAG_ALGORITHM_ATTRIBUTES_DECRYPTION:
			if (decryptionCipher == null)
				decryptionCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
			key.init(decryptionCipher, Cipher.MODE_DECRYPT);
			break;
		case NeoPGPApplet.TAG_ALGORITHM_ATTRIBUTES_AUTHENTICATION:
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
