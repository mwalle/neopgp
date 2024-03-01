// SPDX-License-Identifier: GPL-3.0-or-later
package javacardx.framework.tlv;

public final class ConstructedBERTLV extends BERTLV {
	public ConstructedBERTLV(short numTLVs) {}

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
			if (BERTag.tagNumber(berTagArray, bTagOff) == BERTag.tagNumber(berTLVArray, startOffset) &&
			    BERTag.isConstructed(berTagArray, bTagOff) == BERTag.isConstructed(berTLVArray, startOffset) &&
			    BERTag.tagClass(berTagArray, bTagOff) == BERTag.tagClass(berTLVArray, startOffset))
				return startOffset;

			startOffset = next(berTLVArray, startOffset);
		}

		return -1;
	}

	public static short append(byte[] berTLVInArray, short bTLVInOff, byte[] berTLVOutArray, short bTLVOutOff) {
		return 0;
	}

	public short init(byte[] bArray, short bOff, short bLen) {
		return 0;
	}

	public short init(ConstructedBERTag tag, BERTLV aTLV) {
		return 0;
	}

	public short init(ConstructedBERTag tag, byte[] vArray, short vOff, short vLen) {
		return 0;
	}

	public short append(BERTLV aTLV) {
		return 0;
	}

	public short delete(BERTLV aTLV, short occurrenceNum) {
		return 0;
	}

	public BERTLV find(BERTag tag) {
		return null;
	}

	public BERTLV findNext(BERTag tag, BERTLV aTLV, short occurrenceNum) {
		return null;
	}
}
