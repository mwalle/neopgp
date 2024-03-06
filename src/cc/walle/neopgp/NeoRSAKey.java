// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

public class NeoRSAKey extends NeoKey {
	public static final byte IMPORT_FORMAT_CRT_W_MODULUS = 0x03;
	public static final byte TAG_RSA_PUBLIC_KEY_MODULUS = (byte)0x81;
	public static final byte TAG_RSA_PUBLIC_KEY_EXPONENT = (byte)0x82;

	public static final byte DIGEST_INFO_SHA256_LENGTH = (byte)51;
	public static final byte DIGEST_INFO_SHA384_LENGTH = (byte)67;
	public static final byte DIGEST_INFO_SHA512_LENGTH = (byte)83;

	private short modulusSize;
	private short publicExponentSize;

	/* borrowed from KeyStore */
	private Cipher encryptCipher;
	private Cipher decryptCipher;

	public NeoRSAKey(short size) {
		super();
		modulusSize = size;
		publicExponentSize = 17;

		publicKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, size, false);
		privateKey = (RSAPrivateCrtKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, size, false);
		keyPair = new KeyPair(publicKey, privateKey);
	}

	public void init(Cipher[] ciphers) {
		encryptCipher = ciphers[NeoKeyStore.ENCRYPT];
		decryptCipher = ciphers[NeoKeyStore.DECRYPT];
	}

	public short getAlgorithmAttributes(byte[] buf, short off) {
		buf[off++] = NeoKey.ALGORITHM_ID_RSA;
		off = Util.setShort(buf, off, modulusSize);
		off = Util.setShort(buf, off, publicExponentSize);
		buf[off++] = NeoRSAKey.IMPORT_FORMAT_CRT_W_MODULUS;

		return off;
	}

	public void generate() {
		boolean needTransaction = JCSystem.getTransactionDepth() == 0;

		if (needTransaction)
			JCSystem.beginTransaction();

		super.generate();
		encryptCipher.init(privateKey, Cipher.MODE_ENCRYPT);
		decryptCipher.init(privateKey, Cipher.MODE_DECRYPT);

		if (needTransaction)
			JCSystem.commitTransaction();
	}

	public short getPublicKey(byte[] buf, short off) {
		short lengthOffset1, lengthOffset2;

		if (status == STATUS_NOT_PRESENT)
			ISOException.throwIt(NeoPGPApplet.SW_REFERENCE_DATA_NOT_FOUND);

		off = NeoPGPApplet.setTag(buf, off, NeoKey.TAG_PUBLIC_KEY);
		off = lengthOffset1 = NeoPGPApplet.prepareLength3(buf, off);

		off = NeoPGPApplet.setTag(buf, off, TAG_RSA_PUBLIC_KEY_MODULUS);
		off = lengthOffset2 = NeoPGPApplet.prepareLength3(buf, off);

		off += ((RSAPublicKey)publicKey).getModulus(buf, off);
		NeoPGPApplet.setPreparedLength3(buf, off, lengthOffset2);

		off = NeoPGPApplet.setTag(buf, off, TAG_RSA_PUBLIC_KEY_EXPONENT);
		off = lengthOffset2 = NeoPGPApplet.prepareLength1(buf, off);
		off += ((RSAPublicKey)publicKey).getExponent(buf, off);
		NeoPGPApplet.setPreparedLength1(buf, off, lengthOffset2);
		NeoPGPApplet.setPreparedLength3(buf, off, lengthOffset1);

		return off;
	}

	public short sign(byte[] buf, short off, short len) {
		switch (len) {
		case DIGEST_INFO_SHA256_LENGTH:
			break;
		case DIGEST_INFO_SHA384_LENGTH:
			break;
		case DIGEST_INFO_SHA512_LENGTH:
			break;
		default:
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			return 0;
		}

		return encryptCipher.doFinal(buf, off, len, buf, (short)0);
	}

	public short decipher(byte[] buf, short off, short len) {
		if (buf[off] != NeoPGPApplet.PSO_PAD_RSA)
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);

		return decryptCipher.doFinal(buf, (short)(off + 1), (short)(len - 1), buf, (short)0);
	}

	public short authenticate(byte[] buf, short off, short len) {
		return encryptCipher.doFinal(buf, off, len, buf, (short)0);
	}
}
