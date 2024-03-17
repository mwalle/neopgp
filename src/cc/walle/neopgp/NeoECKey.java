// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.Signature;

public abstract class NeoECKey extends NeoKey {
	public static final byte TAG_EC_PUBLIC_KEY = (byte)0x86;

	private static final byte[] BER_TAG_INTEGER = { (byte)0x02 };
	private static final byte[] BER_TAG_PUBLIC_KEY = { (byte)0x7f, (byte)0x49 };
	private static final byte[] BER_TAG_EXTERNAL_PUBLIC_KEY = { (byte)0x86 };

	public static final byte TAG_PRIVATE_KEY_S = (byte)0x92;
	public static final byte TAG_PUBLIC_KEY_W = (byte)0x99;

	private byte[] oid;
	private byte[] p, a, b, G, n;
	private short k;

	private KeyAgreement keyAgreement;
	private Signature[] signatures;

	public NeoECKey(byte keyRef, byte[] oid, short size,
			byte[] p, byte[] a, byte[] b, byte[] G,
			byte[] n, short k) {
		super(keyRef);

		this.oid = oid;
		this.p = p;
		this.a = a;
		this.b = b;
		this.G = G;
		this.n = n;
		this.k = k;

		publicKey = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, size, false);
		privateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, size, false);
		keyPair = new KeyPair(publicKey, privateKey);
	}

	public void init(Signature[] signatures) {
		this.signatures = signatures;
	}

	public void init(KeyAgreement keyAgreement) {
		this.keyAgreement = keyAgreement;
	}

	private void setECParameters(ECKey key, byte[] p, byte[] a, byte[] b, byte[] G, byte[] n, short k) {
		key.setFieldFP(p, (short)0, (short)p.length);
		key.setA(a, (short)0, (short)a.length);
		key.setB(b, (short)0, (short)b.length);
		key.setG(G, (short)0, (short)G.length);
		key.setR(n, (short)0, (short)n.length);
		key.setK(k);
	}

	public void clear() {
		super.clear();
		setECParameters((ECPublicKey)publicKey, p, a, b, G, n, k);
		setECParameters((ECPrivateKey)privateKey, p, a, b, G, n, k);
	}

	public void update() {
		switch (keyRef) {
		case NeoKey.DECRYPTION_KEY:
			keyAgreement.init(privateKey);
			break;
		case NeoKey.SIGNATURE_KEY:
		case NeoKey.AUTHENTICATION_KEY:
			signatures[NeoKeyStore.SHA1].init(privateKey, Signature.MODE_SIGN);
			signatures[NeoKeyStore.SHA224].init(privateKey, Signature.MODE_SIGN);
			signatures[NeoKeyStore.SHA256].init(privateKey, Signature.MODE_SIGN);
			signatures[NeoKeyStore.SHA384].init(privateKey, Signature.MODE_SIGN);
			signatures[NeoKeyStore.SHA512].init(privateKey, Signature.MODE_SIGN);
			break;
		}
	}

	public short getAlgorithmAttributes(byte[] buf, short off) {
		buf[off++] = NeoKey.ALGORITHM_ID_ECDSA;
		off = Util.arrayCopyNonAtomic(oid, (short)0, buf, off, (short)oid.length);
		buf[off++] = (byte)0xff;

		return off;
	}

	public boolean matchAlgorithmAttributes(byte[] buf, short off, short len) {
		if (buf[off] != NeoKey.ALGORITHM_ID_ECDSA &&
			buf[off] != NeoKey.ALGORITHM_ID_ECDH)
			return false;
		off++;
		if (Util.arrayCompare(buf, off, oid, (short)0, (short)oid.length) != 0)
			return false;

		/* Ignore the remaining properties, so GnuPG can switch keys. */
		return true;
	}

	private short copyBERTLV(byte[] inBuf, short tlv, byte[] outBuf, short off, short truncate) {

		short valueOffset = NeoBERParser.getValueOffset(inBuf, tlv);
		short length = NeoBERParser.getLength(inBuf, tlv);
		short delta = (short)(length - truncate);

		return Util.arrayCopyNonAtomic(inBuf, (short)(valueOffset + delta), outBuf, off, (short)(length - delta));
	}

	public short getPublicKey(byte[] buf, short off) {
		short lengthOffset1, lengthOffset2;

		if (status == STATUS_NOT_PRESENT)
			ISOException.throwIt(NeoPGPApplet.SW_REFERENCE_DATA_NOT_FOUND);

		off = NeoPGPApplet.setTag(buf, off, NeoKey.TAG_PUBLIC_KEY);
		off = lengthOffset1 = NeoPGPApplet.prepareLength2(buf, off);

		off = NeoPGPApplet.setTag(buf, off, TAG_EC_PUBLIC_KEY);
		off = lengthOffset2 = NeoPGPApplet.prepareLength2(buf, off);
		off += ((ECPublicKey)publicKey).getW(buf, off);

		NeoPGPApplet.setPreparedLength2(buf, off, lengthOffset2);
		NeoPGPApplet.setPreparedLength2(buf, off, lengthOffset1);

		return off;
	}

	public short getImportBufferSize() {
		/*
		 * The values for even the largest key (521bits) will fit
		 * into the APDU buffer */
		return (short)0;
	}

	public void doImportKey(byte[] buf, short templateOffset, short templateLength,
				short dataOffset, short dataLength) {
		short off;
		short sLength = 0, wLength = 0;

		for (off = templateOffset;
		     off < (short)(templateOffset + templateLength);
		     off = NeoBERParser.getValueOffset(buf, off)) {
			switch (buf[off]) {
			case TAG_PRIVATE_KEY_S:
				sLength = NeoBERParser.getLength(buf, off);
				break;
			case TAG_PUBLIC_KEY_W:
				wLength = NeoBERParser.getLength(buf, off);
				break;
			}
		}

		if (sLength == (short)0 || wLength == (short)0)
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);

		if ((short)(sLength + wLength) > dataLength)
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);

		off = dataOffset;
		((ECPrivateKey)privateKey).setS(buf, off, sLength);
		off += sLength;
		((ECPublicKey)publicKey).setW(buf, off, wLength);
	}

	private short signCommon(byte[] buf, short off, short len) {
		Signature signature;
		short tlvR;
		short tlvS;

		switch (len) {
		case MessageDigest.LENGTH_SHA:
			signature = signatures[NeoKeyStore.SHA1];
			break;
		case MessageDigest.LENGTH_SHA_224:
			signature = signatures[NeoKeyStore.SHA224];
			break;
		case MessageDigest.LENGTH_SHA_256:
			signature = signatures[NeoKeyStore.SHA256];
			break;
		case MessageDigest.LENGTH_SHA_384:
			signature = signatures[NeoKeyStore.SHA384];
			break;
		case MessageDigest.LENGTH_SHA_512:
			signature = signatures[NeoKeyStore.SHA512];
			break;
		default:
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			return 0;
		}

		/*
		 * This will return two integers in an DER encoded form, decode
		 * it an just return both integers.
		 * DER coding is as follows:
		 * SEQUENCE <l> INTEGER <l> <r> INTEGER <l> <s>
		 */
		len = signature.signPreComputedHash(buf, off, len, buf, (short)0);

		tlvR = NeoBERParser.find(buf, (short)0, BER_TAG_INTEGER, (short)0);
		tlvS = NeoBERParser.findNext(buf, (short)0, tlvR, BER_TAG_INTEGER, (short)0);
		off = copyBERTLV(buf, tlvR, buf, (short)0, (short)(privateKey.getSize() / 8));
		off = copyBERTLV(buf, tlvS, buf, off, (short)(privateKey.getSize() / 8));

		return off;
	}

	public short sign(byte[] buf, short off, short len) {
		if (keyRef != NeoKey.SIGNATURE_KEY)
			ISOException.throwIt(ISO7816.SW_UNKNOWN);

		return signCommon(buf, off, len);
	}

	public short decipher(byte[] buf, short off, short len) {
		short tlv, tlvOffset, tlvLength;

		if (keyRef != NeoKey.DECRYPTION_KEY)
			ISOException.throwIt(ISO7816.SW_UNKNOWN);

		if (buf[off] != NeoPGPApplet.PSO_PAD_ECDH)
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);

		tlv = NeoBERParser.find(buf, off, BER_TAG_PUBLIC_KEY, (short)0);
		if (tlv < (short)0)
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);

		tlv = NeoBERParser.find(buf, tlv, BER_TAG_EXTERNAL_PUBLIC_KEY, (short)0);
		if (tlv < (short)0)
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);

		tlvOffset = NeoBERParser.getValueOffset(buf, tlv);
		tlvLength = NeoBERParser.getLength(buf, tlv);
		if ((short)(tlvOffset + tlvLength) > (short)(off + len))
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);

		return keyAgreement.generateSecret(buf, tlvOffset, tlvLength, buf, (short)0);
	}

	public short authenticate(byte[] buf, short off, short len) {
		if (keyRef != NeoKey.AUTHENTICATION_KEY)
			ISOException.throwIt(ISO7816.SW_UNKNOWN);

		return signCommon(buf, off, len);
	}
}
