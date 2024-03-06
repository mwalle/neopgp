// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacardx.crypto.Cipher;

public class NeoKeyStore {
	public static final byte ENCRYPT = 0;
	public static final byte DECRYPT = 1;

	private short algorithmAttributesTag;
	private NeoKey[] keyStore;

	/* needed by RSA keys */
	private Cipher[] ciphers;

	public NeoKeyStore(short algorithmAttributesTag, short bitmask) {
		NeoRSAKey rsakey;
		short n = 0;

		this.algorithmAttributesTag = algorithmAttributesTag;

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
			addRSAKey(n++, new NeoRSAKey((short)2048));
		if ((bitmask & (short)0x0002) == (short)0x0002)
			addRSAKey(n++, new NeoRSAKey((short)3072));
		if ((bitmask & (short)0x0004) == (short)0x0004)
			addRSAKey(n++, new NeoRSAKey((short)4096));
	}

	private void addRSAKey(short n, NeoRSAKey key) {
		if (ciphers == null) {
			ciphers = new Cipher[2];
			ciphers[ENCRYPT] = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
			ciphers[DECRYPT] = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		}
		key.init(ciphers);
		keyStore[n] = key;
	}

	public NeoKey getDefaultKey() {
		return keyStore[0];
	}

	public void clear() {
		for (short i = 0; i < keyStore.length; i++)
			keyStore[i].clear();
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
