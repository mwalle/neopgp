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
import javacardx.framework.tlv.BERTLV;
import javacardx.framework.tlv.ConstructedBERTLV;
import javacardx.framework.tlv.PrimitiveBERTLV;

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

	/* borrowed from KeyStore */
	private Cipher encryptCipher;
	private Cipher decryptCipher;

	public NeoRSAKey(short size) {
		super();

		/*
		 * If the exponent in the public key is not pre-initialized,
		 * 65537 wil be used. Thus it has 17 bits.
		 */
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

	public void generateKey() {
		boolean needTransaction = JCSystem.getTransactionDepth() == 0;

		if (needTransaction)
			JCSystem.beginTransaction();

		super.generateKey();
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

	public void doImportKey(byte[] buf, short off, short len) {
		RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey)privateKey;
		RSAPublicKey rsaPublicKey = (RSAPublicKey)publicKey;
		short templateTLVLength;
		short templateTLV, dataTLV, templateTLVOffset;
		short exponentLength = 0, modulusLength = 0, pLength = 0;
		short qLength = 0, pqLength = 0, dp1Length = 0, dq1Length = 0;

		/*
		 * Oh the horror. The contents of the 7F48 tag looks like BER
		 * encoded but it's missing the actual content. That is then
		 * part of the 5F48 tag. Even worse, the 7F48 tag refers to a
		 * constructed one, but because the value is missing, it's not
		 * and we cannot use the javacardx.framework.tlv utils. Or can
		 * we...
		 */
		templateTLV = ConstructedBERTLV.find(buf, off, NeoKey.BER_TAG_PRIVATE_KEY_TEMPLATE, (short)0);
		if (templateTLV < (short)0)
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);

		dataTLV = ConstructedBERTLV.findNext(buf, off, templateTLV, NeoKey.BER_TAG_PRIVATE_KEY_DATA, (short)0);
		if (dataTLV < (short)0)
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);

		/*
		 * Here be dragons. We clear the constructed bit so we can
		 * actually use PrimitiveBERTLV.getValueOffset().
		 */
		templateTLVLength = BERTLV.getLength(buf, templateTLV);
		buf[templateTLV] &= (byte)~0x20;
		templateTLVOffset = PrimitiveBERTLV.getValueOffset(buf, templateTLV);

		for (off = templateTLVOffset;
		     off < (short)(templateTLVOffset + templateTLVLength);
		     off = PrimitiveBERTLV.getValueOffset(buf, off)) {
			switch (buf[off]) {
			case TAG_PUBLIC_KEY_EXPONENT:
				exponentLength = BERTLV.getLength(buf, off);
				break;
			case TAG_PRIVATE_KEY_P:
				pLength = BERTLV.getLength(buf, off);
				break;
			case TAG_PRIVATE_KEY_Q:
				qLength = BERTLV.getLength(buf, off);
				break;
			case TAG_PRIVATE_KEY_PQ:
				pqLength = BERTLV.getLength(buf, off);
				break;
			case TAG_PRIVATE_KEY_DP1:
				dp1Length = BERTLV.getLength(buf, off);
				break;
			case TAG_PRIVATE_KEY_DQ1:
				dq1Length = BERTLV.getLength(buf, off);
				break;
			case TAG_PUBLIC_KEY_MODULUS:
				modulusLength = BERTLV.getLength(buf, off);
				break;
			}
		}

		if (exponentLength == (short)0 || modulusLength == (short)0 ||
				pLength == (short)0 || qLength == (short)0 ||
				pqLength == (short)0 || dp1Length == (short)0 ||
				dq1Length == (short)0)
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);

		off = PrimitiveBERTLV.getValueOffset(buf, dataTLV);

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
