// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;

public class NeoPIN extends OwnerPIN {
	public static final byte MAX_RETRIES = (byte)3;
	public static final byte MAX_LENGTH = (byte)64;
	public static final byte MODE_NONE = (byte)-1;

	private byte actualLength;
	private byte minLength;
	private byte[] defaultPIN = null;
	private boolean[] modeValid = null;

	public NeoPIN(byte minLength) {
		super(MAX_RETRIES, MAX_LENGTH);
		this.minLength = minLength;
		actualLength = 0;
	}

	public NeoPIN(byte minLength, byte[] defaultPIN) {
		this(minLength);
		this.defaultPIN = defaultPIN;
	}

	public NeoPIN(byte minLength, byte[] defaultPIN, byte numModes) {
		this(minLength, defaultPIN);

		if (numModes != 0)
			modeValid = JCSystem.makeTransientBooleanArray(numModes, JCSystem.CLEAR_ON_DESELECT);
	}

	public boolean isValidated(byte mode) {
		if (!isValidated())
			return false;
		if (mode != MODE_NONE)
			return modeValid[mode];

		return true;
	}

	public void reset(byte mode) {
		reset();
		if (mode != MODE_NONE)
			modeValid[mode] = false;
	}

	public void clear() {
		if (defaultPIN != null) {
			update(defaultPIN, (short)0, (byte)defaultPIN.length);
		} else {
			/*
			 * Drain the remaining tries counter, because we cannot
			 * set it directly. That is only possible with OwnerPINx
			 * since JC3.0.5.
			 */
			while (getTriesRemaining() > 0) {
				try {
					super.check(null, (short)0, (byte)0);
				} catch (NullPointerException e) { }
			}
			actualLength = 0;
		}
	}

	public void change(byte[] buf, short off, short length, NeoPIN pin) {
		short sanitizedLength;

		if (length < (short)(minLength + pin.minLength))
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (length > (short)(2 * MAX_LENGTH))
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		/* Don't access buffer out of bounds */
		sanitizedLength = pin.actualLength;
		if (sanitizedLength > length)
			sanitizedLength = length;

		if (!pin.check(buf, off, sanitizedLength))
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

		if ((short)(length - pin.actualLength) < minLength)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		update(buf, (short)(off + pin.actualLength), (short)(length - pin.actualLength));
	}

	public void change(byte[] buf, short off, short length) {
		change(buf, off, length, this);
	}

	public void assertValidated() throws ISOException {
		assertValidated(MODE_NONE);
	}

	public void assertValidated(byte mode) throws ISOException {
		if (!isValidated(mode))
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
	}

	public boolean check(byte[] pin, short offset, short length) {
		if (length < minLength || length > MAX_LENGTH)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		return super.check(pin, offset, (byte)length);
	}

	public boolean check(byte[] pin, short offset, short length, byte mode) {
		if (!check(pin, offset, length)) {
			if (mode != MODE_NONE)
				modeValid[mode] = false;
			return false;
		}

		if (mode != MODE_NONE)
			modeValid[mode] = true;

		return true;
	}

	public void update(byte[] pin, short offset, short length) {
		if (length > MAX_LENGTH)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		update(pin, offset, (byte)length);
	}

	public void update(byte[] pin, short offset, byte length) {
		boolean needTransaction = JCSystem.getTransactionDepth() == 0;

		if (length < minLength || length > MAX_LENGTH)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		/* We need to update the length and actual PIN atomically. */
		if (needTransaction)
			JCSystem.beginTransaction();

		actualLength = length;
		super.update(pin, offset, length);

		if (needTransaction)
			JCSystem.commitTransaction();
	}
}
