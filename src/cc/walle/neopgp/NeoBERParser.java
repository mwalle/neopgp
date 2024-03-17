// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import javacard.framework.Util;

/*
 * This is bascially a reimplementation of javacardx.framework.tlv.
 *
 * Unfortunately, the OpenPGP specification has some APDUs that look
 * like BER encoded, but aren't. For example, the original implementation
 * will throw a TLVException(MALFORMED_TLV) when parsing the APDU to
 * import keys (instruction DBh).
 *
 * This implementation doesn't verify the TLVs nor will it enforce that
 * a tag will match the constructed bit (20h).
 */

public class NeoBERParser {
	private NeoBERParser() {}

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

	public static short getLengthOffset(byte[] berTLVArray, short bOff) {
		return (short)(bOff + size(berTLVArray, bOff));
	}

	public static short getValueOffset(byte[] berTLVArray, short bOff) {
		bOff = getLengthOffset(berTLVArray, bOff);

		if ((berTLVArray[bOff] & (byte)0x80) == (byte)0x80) {
			byte tmp = (byte)(berTLVArray[bOff] & (byte)0x7f);
			if (tmp > 2)
				TLVException.throwIt(TLVException.TLV_SIZE_GREATER_THAN_32767);

			bOff += tmp;
		}

		return (short)(bOff + (short)1);
	}

	public static short getLength(byte[] berTLVArray, short bOff) {
		bOff = getLengthOffset(berTLVArray, bOff);

		if ((berTLVArray[bOff] & 0x80) == 0)
			return berTLVArray[bOff];

		switch ((berTLVArray[bOff] & 0x7f)) {
		case 1:
			return (short)(berTLVArray[(short)(bOff + 1)] & 0xff);
		case 2:
			return Util.getShort(berTLVArray, (short)(bOff + 1));
		default:
			TLVException.throwIt(TLVException.ILLEGAL_SIZE);
			return 0;
		}
	}

	public static short getTag(byte[] berTLVArray, short bTLVOff, byte[] berTagArray, short bTagOff) {
		short size = size(berTLVArray, bTLVOff);
		Util.arrayCopyNonAtomic(berTLVArray, bTLVOff, berTagArray, bTagOff, size);
		return size;
	}

	public static short find(byte[] berTLVArray, short bTLVOff, byte[] berTagArray, short bTagOff) {
		short startOffset = getValueOffset(berTLVArray, bTLVOff);
		return findCommon(berTLVArray, bTLVOff, startOffset, berTagArray, bTagOff);
	}

	public static short findNext(byte[] berTLVArray, short bTLVOff, short startOffset, byte[] berTagArray, short bTagOff) {
		startOffset = next(berTLVArray, startOffset);
		return findCommon(berTLVArray, bTLVOff, startOffset, berTagArray, bTagOff);
	}

	private static short next(byte[] berTLVArray, short startOffset) {
		return (short)(getValueOffset(berTLVArray, startOffset) + getLength(berTLVArray, startOffset));
	}

	private static short findCommon(byte[] berTLVArray, short bTLVOff, short startOffset, byte[] berTagArray, short bTagOff) {
		short valueLength = getLength(berTLVArray, bTLVOff);
		short valueOffset = getValueOffset(berTLVArray, bTLVOff);

		while (startOffset < (short)(valueOffset + valueLength)) {
			if (tagNumber(berTagArray, bTagOff) == tagNumber(berTLVArray, startOffset) &&
			    isConstructed(berTagArray, bTagOff) == isConstructed(berTLVArray, startOffset) &&
			    tagClass(berTagArray, bTagOff) == tagClass(berTLVArray, startOffset))
				return startOffset;

			startOffset = next(berTLVArray, startOffset);
		}

		return -1;
	}
}
