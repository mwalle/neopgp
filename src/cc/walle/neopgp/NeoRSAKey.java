// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
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

	public static final byte TAG_PUBLIC_KEY_EXPONENT = (byte)0x91;
	public static final byte TAG_PRIVATE_KEY_P = (byte)0x92;
	public static final byte TAG_PRIVATE_KEY_Q = (byte)0x93;
	public static final byte TAG_PRIVATE_KEY_PQ = (byte)0x94;
	public static final byte TAG_PRIVATE_KEY_DP1 = (byte)0x95;
	public static final byte TAG_PRIVATE_KEY_DQ1 = (byte)0x96;
	public static final byte TAG_PUBLIC_KEY_MODULUS = (byte)0x97;

	public static final byte DIGEST_INFO_SHA256_LENGTH = (byte)51;
	public static final byte DIGEST_INFO_SHA384_LENGTH = (byte)67;
	public static final byte DIGEST_INFO_SHA512_LENGTH = (byte)83;

	public static final byte ALGORITHM_ATTRIBUTES_LENGTH = (byte)6;

	private short publicExponentSize;
	private byte cipherMode;

	/* borrowed from KeyStore */
	private Cipher cipher;

	public NeoRSAKey(byte keyRef, short size) {
		super(keyRef);

		/*
		 * If the exponent in the public key is not pre-initialized,
		 * 65537 wil be used. Thus it has 17 bits.
		 */
		publicExponentSize = 17;

		publicKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, size, false);
		privateKey = (RSAPrivateCrtKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, size, false);
		keyPair = new KeyPair(publicKey, privateKey);
	}

	public void init(Cipher cipher, byte cipherMode) {
		this.cipher = cipher;
		this.cipherMode = cipherMode;
	}

	public short getAlgorithmAttributes(byte[] buf, short off) {
		buf[off++] = NeoKey.ALGORITHM_ID_RSA;
		off = Util.setShort(buf, off, privateKey.getSize());
		off = Util.setShort(buf, off, publicExponentSize);
		buf[off++] = NeoRSAKey.IMPORT_FORMAT_CRT_W_MODULUS;

		return off;
	}

	public boolean matchAlgorithmAttributes(byte[] buf, short off, short len) {
		if (len != ALGORITHM_ATTRIBUTES_LENGTH)
			return false;
		if (buf[off++] != NeoKey.ALGORITHM_ID_RSA)
			return false;
		if (Util.getShort(buf, off) != privateKey.getSize())
			return false;

		/* Ignore the remaining properties, so GnuPG can switch keys. */
		return true;
	}

	public void update() {
		cipher.init(privateKey, cipherMode);
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

	public short getImportBufferSize() {
		switch (privateKey.getSize()) {
		case 2048:
			return 0x400;
		case 3072:
			return 0x600;
		case 4096:
			return 0x800;
		default:
			ISOException.throwIt(ISO7816.SW_UNKNOWN);
			return 0;
		}
	}

	public void doImportKey(byte[] buf, short templateOffset, short templateLength,
				short dataOffset, short dataLength) {
		short off;
		RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey)privateKey;
		RSAPublicKey rsaPublicKey = (RSAPublicKey)publicKey;
		short exponentLength = 0, modulusLength = 0, pLength = 0;
		short qLength = 0, pqLength = 0, dp1Length = 0, dq1Length = 0;

		for (off = templateOffset;
		     off < (short)(templateOffset + templateLength);
		     off = NeoBERParser.getValueOffset(buf, off)) {
			switch (buf[off]) {
			case TAG_PUBLIC_KEY_EXPONENT:
				exponentLength = NeoBERParser.getLength(buf, off);
				break;
			case TAG_PRIVATE_KEY_P:
				pLength = NeoBERParser.getLength(buf, off);
				break;
			case TAG_PRIVATE_KEY_Q:
				qLength = NeoBERParser.getLength(buf, off);
				break;
			case TAG_PRIVATE_KEY_PQ:
				pqLength = NeoBERParser.getLength(buf, off);
				break;
			case TAG_PRIVATE_KEY_DP1:
				dp1Length = NeoBERParser.getLength(buf, off);
				break;
			case TAG_PRIVATE_KEY_DQ1:
				dq1Length = NeoBERParser.getLength(buf, off);
				break;
			case TAG_PUBLIC_KEY_MODULUS:
				modulusLength = NeoBERParser.getLength(buf, off);
				break;
			}
		}

		if (exponentLength == (short)0 || modulusLength == (short)0 ||
				pLength == (short)0 || qLength == (short)0 ||
				pqLength == (short)0 || dp1Length == (short)0 ||
				dq1Length == (short)0)
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);

		if ((short)(exponentLength + pLength + qLength + pqLength +
			    dp1Length + dq1Length + modulusLength) > dataLength)
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);

		off = dataOffset;
		rsaPublicKey.setExponent(buf, off, exponentLength);
		off += exponentLength;
		rsaPrivateKey.setP(buf, off, pLength);
		off += pLength;
		rsaPrivateKey.setQ(buf, off, qLength);
		off += qLength;
		rsaPrivateKey.setPQ(buf, off, pqLength);
		off += pqLength;
		rsaPrivateKey.setDP1(buf, off, dp1Length);
		off += dp1Length;
		rsaPrivateKey.setDQ1(buf, off, dq1Length);
		off += dq1Length;
		rsaPublicKey.setModulus(buf, off, modulusLength);
	}

	public short sign(byte[] buf, short off, short len) {
		if (keyRef != NeoKey.SIGNATURE_KEY)
			ISOException.throwIt(ISO7816.SW_UNKNOWN);

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

		return cipher.doFinal(buf, off, len, buf, (short)0);
	}

	public short decipher(byte[] buf, short off, short len) {
		if (keyRef != NeoKey.DECRYPTION_KEY)
			ISOException.throwIt(ISO7816.SW_UNKNOWN);

		if (buf[off] != NeoPGPApplet.PSO_PAD_RSA)
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);

		return cipher.doFinal(buf, (short)(off + 1), (short)(len - 1), buf, (short)0);
	}

	public short authenticate(byte[] buf, short off, short len) {
		if (keyRef != NeoKey.AUTHENTICATION_KEY)
			ISOException.throwIt(ISO7816.SW_UNKNOWN);
		return cipher.doFinal(buf, off, len, buf, (short)0);
	}
}
