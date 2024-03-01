package javacardx.framework.tlv;

import javacardx.framework.tlv.TLVException;

public abstract class BERTag {
	public static final byte BER_TAG_CLASS_MASK_UNIVERSAL = 0;
	public static final byte BER_TAG_CLASS_MASK_APPLICATION = 1;
	public static final byte BER_TAG_CLASS_MASK_CONTEXT_SPECIFIC = 2;
	public static final byte BER_TAG_CLASS_MASK_PRIVATE = 3;
	public static final boolean BER_TAG_TYPE_CONSTRUCTED = true;
	public static final boolean BER_TAG_TYPE_PRIMITIVE = false;

	protected BERTag() {}

	public static byte size(byte[] berTagArray, short bOff) throws TLVException {
		return tagNumber(berTagArray, bOff) < 31 ? (byte)1 : (byte)2;
	}

	public static short tagNumber(byte[] berTagArray, short bOff) throws TLVException {
		short number;

		number = (short)(berTagArray[bOff] & 0x1f);
		if (number < 31)
			return number;

		number = (short)(berTagArray[(short)(bOff + 1)] & 0xff);
		if (number < 31)
			TLVException.throwIt(TLVException.MALFORMED_TAG);

		/* for simplicity this only supports two byte tags */
		if (number >= 128)
			TLVException.throwIt(TLVException.ILLEGAL_SIZE);

		return number;
	}

	public static boolean isConstructed(byte[] berTagArray, short bOff) {
		return (berTagArray[bOff] & 0x20) != 0;
	}

	public static byte tagClass(byte[] berTagArray, short bOff) {
		return (byte)((berTagArray[bOff] >> 6) & 0x03);
	}

	public static short toBytes(short tagClass, boolean isConstructed, short tagNumber, byte[] outArray, short bOff) {
		return 0;
	}

	public static boolean verifyFormat(byte[] berTagArray, short bOff) {
		return false;
	}

	public abstract void init(byte[] var1, short var2);

	public static BERTag getInstance(byte[] bArray, short bOff) {
		return null;
	}

	public byte size() {
		return 0;
	}

	public short toBytes(byte[] outBuf, short bOffset) {
		return 0;
	}

	public short tagNumber() {
		return 0;
	}

	public boolean isConstructed() {
		return false;
	}

	public byte tagClass() {
		return 0;
	}

	public boolean equals(BERTag otherTag) {
		return false;
	}
}
