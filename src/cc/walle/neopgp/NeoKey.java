// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.PublicKey;
import javacard.security.PrivateKey;
import javacard.security.KeyPair;

public abstract class NeoKey {
	public static final short TAG_PUBLIC_KEY = (short)0x7f49;
	public static final byte[] BER_TAG_PRIVATE_KEY_TEMPLATE = { (byte)0x7f, (byte)0x48 };
	public static final byte[] BER_TAG_PRIVATE_KEY_DATA = { (byte)0x5f, (byte)0x48 };

	public static final byte ALGORITHM_ID_RSA = (byte)0x01;
	public static final byte ALGORITHM_ID_ECDH = (byte)0x12;
	public static final byte ALGORITHM_ID_ECDSA = (byte)0x13;

	public static final byte STATUS_NOT_PRESENT = 0;
	public static final byte STATUS_GENERATED = 1;
	public static final byte STATUS_IMPORTED = 2;

	/* these are the Key-Refs from the OpenPGP card spec */
	public static final byte SIGNATURE_KEY = 1;
	public static final byte DECRYPTION_KEY = 2;
	public static final byte AUTHENTICATION_KEY = 3;

	protected PublicKey publicKey = null;
	protected PrivateKey privateKey = null;
	protected KeyPair keyPair = null;

	protected NeoByteArray fingerprint = null;
	protected NeoByteArray timestamp = null;
	protected byte status;
	protected byte keyRef;

	public NeoKey(byte keyRef) {
		this.keyRef = keyRef;
		status = STATUS_NOT_PRESENT;
		fingerprint = new NeoFixedByteArray(NeoPGPApplet.FINGERPRINT_LENGTH);
		timestamp = new NeoFixedByteArray(NeoPGPApplet.TIMESTAMP_LENGTH);
	}

	public abstract boolean matchAlgorithmAttributes(byte[] buf, short off, short len);
	public abstract short getAlgorithmAttributes(byte[] buf, short off);
	public abstract short getPublicKey(byte[] buf, short off);
	public abstract void doImportKey(byte[] buf, short off, short len);
	public abstract short getImportBufferSize();
	public abstract void update();
	public abstract short sign(byte[] buf, short off, short len);
	public abstract short decipher(byte[] buf, short off, short len);
	public abstract short authenticate(byte[] buf, short off, short len);

	public void clear() {
		status = STATUS_NOT_PRESENT;
		privateKey.clearKey();
		publicKey.clearKey();
		fingerprint.clear();
		timestamp.clear();
	}

	public void importKey(byte[] buf, short off, short len) {
		try {
			doImportKey(buf, off, len);
			update();
		} catch (CryptoException e) {
			clear();
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		status = STATUS_IMPORTED;
	}

	public void generateKey() {
		keyPair.genKeyPair();
		update();
		status = STATUS_GENERATED;
	}

	public short getStatus(byte[] buf, short off) {
		buf[off++] = status;
		return off;
	}

	public short getFingerprint(byte[] buf, short off) {
		return fingerprint.get(buf, off);
	}

	public short setFingerprint(byte[] buf, short off, short len) {
		return fingerprint.set(buf, off, len);
	}

	public short getTimestamp(byte[] buf, short off) {
		return timestamp.get(buf, off);
	}

	public short setTimestamp(byte[] buf, short off, short len) {
		return timestamp.set(buf, off, len);
	}
}
