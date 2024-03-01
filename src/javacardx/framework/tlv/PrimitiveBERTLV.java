// SPDX-License-Identifier: GPL-3.0-or-later
package javacardx.framework.tlv;

import javacardx.framework.tlv.BERTag;
import javacardx.framework.tlv.TLVException;

public class PrimitiveBERTLV extends BERTLV {
	public PrimitiveBERTLV(short numValueBytes) {}

	public static short getValueOffset(byte[] berTLVArray, short bOff) {
		if (BERTag.isConstructed(berTLVArray, bOff))
			TLVException.throwIt(TLVException.MALFORMED_TLV);

		return BERTLV.getValueOffset(berTLVArray, bOff);
	}

	public static short toBytes(byte[] berTagArray, short berTagOff, byte[] valueArray, short vOff, short vLen, byte[] outBuf, short bOff) {
		return 0;
	}

	public static short appendValue(byte[] berTLVArray, short bTLVOff, byte[] vArray, short vOff, short vLen) {
		return 0;
	}

	public short init(byte[] bArray, short bOff, short bLen) {
		return 0;
	}

	public short init(PrimitiveBERTag tag, byte[] vArray, short vOff, short vLen) {
		return 0;
	}

	public short appendValue(byte[] vArray, short vOff, short vLen) {
		return 0;
	}

	public short replaceValue(byte[] vArray, short vOff, short vLen) {
		return 0;
	}

	public short getValue(byte[] tlvValue, short tOff) {
		return 0;
	}
}
