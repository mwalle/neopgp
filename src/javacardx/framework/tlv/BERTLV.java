// SPDX-License-Identifier: GPL-3.0-or-later
package javacardx.framework.tlv;

import javacard.framework.Util;
import javacardx.framework.tlv.TLVException;

public abstract class BERTLV {
	protected BERTLV() {}

	static short getLengthOffset(byte[] berTLVArray, short bOff) {
		return (short)(bOff + BERTag.size(berTLVArray, bOff));
	}

	static short getValueOffset(byte[] berTLVArray, short bOff) {
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
		short size = BERTag.size(berTLVArray, bTLVOff);
		Util.arrayCopyNonAtomic(berTLVArray, bTLVOff, berTagArray, bTagOff, size);
		return size;
	}

	public static boolean verifyFormat(byte[] berTlvArray, short bOff, short bLen) {
		return false;
	}

	public static BERTLV getInstance(byte[] bArray, short bOff, short bLen) {
		return null;
	}

	public short getLength() {
		return 0;
	}

	public abstract short init(byte[] bArray, short bOff, short bLen);

	public BERTag getTag() {
		return null;
	}

	public short size() {
		return 0;
	}

	public short toBytes(byte[] outBuf, short bOff) {
		return 0;
	}
}
