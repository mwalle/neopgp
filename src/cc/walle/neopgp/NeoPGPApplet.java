// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacardx.apdu.ExtendedLength;

public class NeoPGPApplet extends Applet implements ExtendedLength {
	public static final byte INS_SELECT_DATA = (byte)0xa5;
	public static final byte INS_GET_DATA = (byte)0xca;
	public static final byte INS_GET_NEXT_DATA = (byte)0xcc;
	public static final byte INS_VERIFY = (byte)0x20;
	public static final byte INS_CHANGE_REFERENCE_DATA = (byte)0x24;
	public static final byte INS_RESET_RETRY_COUNTER = (byte)0x2c;
	public static final byte INS_PUT_DATA = (byte)0xda;
	public static final byte INS_IMPORT_KEY = (byte)0xdb;
	public static final byte INS_GENERATE_ASYMMETRIC_KEY_PAIR = (byte)0x47;
	public static final byte INS_PERFORM_SECURITY_OPERATION = (byte)0x2a;
	public static final byte INS_INTERNAL_AUTHENTICATE = (byte)0x88;
	public static final byte INS_GET_RESPONSE = (byte)0xc0;
	public static final byte INS_GET_CHALLENGE = (byte)0x84;
	public static final byte INS_TERMINATE_DF = (byte)0xe6;
	public static final byte INS_ACTIVATE_FILE = (byte)0x44;
	public static final byte INS_MANAGE_SECURITY_ENVIRONMENT = (byte)0x22;

	public static final short TAG_AID = (short)0x004f;
	public static final short TAG_APPLICATION_RELATED_DATA = (short)0x006e;
	public static final short TAG_DISCRETIONARY_DATA_OBJECTS = (short)0x0073;
	public static final short TAG_CARDHOLDER_RELATED_DATA = (short)0x0065;
	public static final short TAG_HISTORICAL_BYTES = (short)0x5f52;
	public static final short TAG_EXTENDED_LENGTH_INFORMATION = (short)0x7f66;
	public static final short TAG_PW_STATUS_BYTES = (short)0x00c4;
	public static final short TAG_EXTENDED_CAPABILITIES = (short)0x00c0;
	public static final short TAG_ALGORITHM_ATTRIBUTES_SIGNATURE = (short)0x00c1;
	public static final short TAG_ALGORITHM_ATTRIBUTES_DECRYPTION = (short)0x00c2;
	public static final short TAG_ALGORITHM_ATTRIBUTES_AUTHENTICATION = (short)0x00c3;
	public static final short TAG_NAME = (short)0x005b;
	public static final short TAG_LANGUAGE = (short)0x5f2d;
	public static final short TAG_SEX = (short)0x5f35;
	public static final short TAG_URL = (short)0x5f50;
	public static final short TAG_LOGIN = (short)0x005e;
	public static final short TAG_KEY_FINGERPRINTS = (short)0x00c5;
	public static final short TAG_KEY_GENERATION_TIMESTAMP = (short)0x00cd;
	public static final short TAG_CA_FINGERPRINTS = (short)0x00c6;
	public static final short TAG_SIGNATURE_KEY_FINGERPRINT = (short)0x00c7;
	public static final short TAG_DECRYPTION_KEY_FINGERPRINT = (short)0x00c8;
	public static final short TAG_AUTHENTICATION_KEY_FINGERPRINT = (short)0x00c9;
	public static final short TAG_SIGNATURE_KEY_TIMESTAMP = (short)0x00ce;
	public static final short TAG_DECRYPTION_KEY_TIMESTAMP = (short)0x00cf;
	public static final short TAG_AUTHENTICATION_KEY_TIMESTAMP = (short)0x00d0;
	public static final short TAG_CA1_FINGERPRINT = (short)0x00ca;
	public static final short TAG_CA2_FINGERPRINT = (short)0x00cb;
	public static final short TAG_CA3_FINGERPRINT = (short)0x00cc;
	public static final short TAG_SECURITY_SUPPORT_TEMPLATE = (short)0x007a;
	public static final short TAG_DIGITAL_SIGNATURE_COUNTER = (short)0x0093;
	public static final short TAG_RESET_CODE = (short)0x00d3;
	public static final short TAG_KEY_INFORMATION = (short)0x00de;
	public static final short TAG_ALGORITHM_INFORMATION = (short)0x00fa;
	public static final short TAG_EXTENDED_HEADER_LIST = (short)0x004d;

	public static final byte USER_PIN_MIN_LENGTH = (byte)6;
	public static final byte ADMIN_PIN_MIN_LENGTH = (byte)8;
	public static final byte USER_PUK_MIN_LENGTH = (byte)8;

	public static final byte FINGERPRINT_LENGTH = (byte)20;
	public static final byte TIMESTAMP_LENGTH = (byte)4;

	public static final byte VERIFY_P1_CHECK = (byte)0x00;
	public static final byte VERIFY_P1_RESET = (byte)0xff;
	public static final byte VERIFY_P2_PW1_CDS = (byte)0x81;
	public static final byte VERIFY_P2_PW1 = (byte)0x82;
	public static final byte VERIFY_P2_PW3 = (byte)0x83;

	public static final byte GENKEY_P1_GENERATE = (byte)0x80;
	public static final byte GENKEY_P1_READ_PUBLICKEY = (byte)0x81;
	public static final byte GENKEY_CRT_SIGNATURE_KEY = (byte)0xb6;
	public static final byte GENKEY_CRT_DECRYPTION_KEY = (byte)0xb8;
	public static final byte GENKEY_CRT_AUTHENTICATION_KEY = (byte)0xa4;

	public static final short PSO_OP_COMPUTE_DIGITAL_SIGNATURE = (short)0x9e9a;
	public static final short PSO_OP_DECIPHER = (short)0x8086;
	public static final short PSO_OP_ENCIPHER = (short)0x8680;

	public static final byte PSO_PAD_RSA = (byte)0x00;
	public static final byte PSO_PAD_AES = (byte)0x02;
	public static final byte PSO_PAD_ECDH = (byte)0xa6;

	public static final byte CHANGE_REFERENCE_DATA_P2_PW1 = (byte)0x81;
	public static final byte CHANGE_REFERENCE_DATA_P2_PW3 = (byte)0x83;

	public static final byte RESET_RETRY_COUNTER_P1_BY_RC = (byte)0x00;
	public static final byte RESET_RETRY_COUNTER_P1_BY_PW3 = (byte)0x02;
	public static final byte RESET_RETRY_COUNTER_P2_PW1 = (byte)0x81;

	private static final byte[] BER_TAG_SIGNATURE_KEY = { (byte)0xb6 };
	private static final byte[] BER_TAG_DECRYPTION_KEY = { (byte)0xb8 };
	private static final byte[] BER_TAG_AUTHENTICATION_KEY = { (byte)0xa4 };

	public static final short SW_TERMINATED = (short)0x6285;
	/* from gnuk, name from ISO7816-4 */
	public static final short SW_REFERENCE_DATA_NOT_FOUND = (short)0x6a88;

	public static final byte[] DEFAULT_USER_PIN = {
		'1', '2', '3', '4', '5', '6',
	};

	public static final byte[] DEFAULT_ADMIN_PIN = {
		'1', '2', '3', '4', '5', '6', '7', '8',
	};

	public static final byte[] DEFAULT_LANGUAGE = {
		'e', 'n',
	};

	public static final byte[] DEFAULT_SEX = {
		'0',
	};

	public static final short CFG_NO_KEYGEN_TRANSACTION = (short)0x0001;

	private boolean cardTerminated;
	private short keyBitmask = (short)0x0008;
	private short cardConfiguration;

	private NeoPIN userPIN = null;
	private NeoPIN adminPIN = null;
	private NeoPIN userPUK = null;

	private NeoByteArray sex = null;
	private NeoByteArray name = null;
	private NeoByteArray language = null;
	private NeoByteArray url = null;
	private NeoByteArray login = null;
	public static final byte NAME_MAX_LENGTH = (byte)39;
	public static final byte LANGUAGE_MAX_LENGTH = (byte)8;
	public static final short SPECIAL_DO_MAX_LENGTH = (short)0x100;

	private NeoKeyStore signatureKeyStore;
	private NeoKey signatureKey;
	private NeoKeyStore decryptionKeyStore;
	private NeoKey decryptionKey;
	private NeoKeyStore authenticationKeyStore;
	private NeoKey authenticationKey;

	private NeoByteArray[] caFingerprints = null;
	private byte[] digitalSignatureCounter = null;

	private static final byte USER_PIN_MODE_NORMAL = (byte)0;
	private static final byte USER_PIN_MODE_CDS = (byte)1;
	private byte[] tmpBuffer = null;

	private NeoPGPApplet(byte[] buf, short off, short len) {
		if (len >= (short)2)
			keyBitmask = Util.getShort(buf, off);
		if (len >= (short)4)
			cardConfiguration = Util.getShort(buf, (short)(off + 2));

		userPIN = new NeoPIN(USER_PIN_MIN_LENGTH, DEFAULT_USER_PIN, (byte)2);
		adminPIN = new NeoPIN(ADMIN_PIN_MIN_LENGTH, DEFAULT_ADMIN_PIN);
		userPUK = new NeoPIN(USER_PUK_MIN_LENGTH);
		name = new NeoByteArrayWithLength(NAME_MAX_LENGTH);
		language = new NeoByteArrayWithLength(LANGUAGE_MAX_LENGTH, DEFAULT_LANGUAGE);
		url = new NeoByteArrayWithLength(SPECIAL_DO_MAX_LENGTH);
		login = new NeoByteArrayWithLength(SPECIAL_DO_MAX_LENGTH);
		sex = new NeoFixedByteArray((short)1, DEFAULT_SEX);

		signatureKeyStore = new NeoKeyStore(NeoKey.SIGNATURE_KEY, keyBitmask);
		decryptionKeyStore = new NeoKeyStore(NeoKey.DECRYPTION_KEY, keyBitmask);
		authenticationKeyStore = new NeoKeyStore(NeoKey.AUTHENTICATION_KEY, keyBitmask);
		signatureKey = signatureKeyStore.getDefaultKey();
		decryptionKey = decryptionKeyStore.getDefaultKey();
		authenticationKey = authenticationKeyStore.getDefaultKey();

		caFingerprints = new NeoFixedByteArray[3];
		for (byte i = 0; i < caFingerprints.length; i++)
			caFingerprints[i] = new NeoFixedByteArray(FINGERPRINT_LENGTH);
		digitalSignatureCounter = new byte[3];

		tmpBuffer = createTmpBuffer();
	}

	private byte[] createTmpBuffer() {
		short size = 0;
		short tmp;

		tmp = signatureKeyStore.getImportBufferSize();
		if (size < tmp)
			size = tmp;
		tmp = decryptionKeyStore.getImportBufferSize();
		if (size < tmp)
			size = tmp;
		tmp = authenticationKeyStore.getImportBufferSize();
		if (size < tmp)
			size = tmp;

		if (size == 0)
			return null;

		return JCSystem.makeTransientByteArray(size, JCSystem.CLEAR_ON_DESELECT);
	}

	private boolean hasConfiguration(short mask) {
		return (cardConfiguration & mask) != (short)0;
	}

	public static void install(byte[] buf, short off, byte len) {
		short aidOffset = off;
		short aidLength = buf[off];
		short infoOffset = (short)(aidOffset + aidLength + 1);
		short infoLength = buf[infoOffset];
		short paramsOffset = (short)(infoOffset + infoLength + 1);
		short paramsLength = buf[paramsOffset];

		NeoPGPApplet app = new NeoPGPApplet(buf, (short)(paramsOffset + 1), paramsLength);

		app.register(buf, (short)(off + 1), buf[off]);
		app.reset();
	}

	public static short setLength3(byte[] buf, short off, short len) {
		buf[off++] = (byte)0x82;
		return Util.setShort(buf, off, len);
	}

	public static short setLength2(byte[] buf, short off, short len) {
		buf[off++] = (byte)0x81;
		buf[off++] = (byte)(len & 0xff);
		return off;
	}

	public static short setLength1(byte[] buf, short off, short len) {
		buf[off++] = (byte)(len & 0x7f);
		return off;
	}

	public static short setLength(byte[] buf, short off, short len) {
		if (len >= 256)
			off = setLength3(buf, off, len);
		else if (len >= 128)
			off = setLength2(buf, off, len);
		else
			off = setLength1(buf, off, len);
		return off;
	}

	public static short prepareLength3(byte[] buf, short off) {
		return (short)(off + 3);
	}

	public static short prepareLength2(byte[] buf, short off) {
		return (short)(off + 2);
	}

	public static short prepareLength1(byte[] buf, short off) {
		return (short)(off + 1);
	}

	public static void setPreparedLength3(byte[] buf, short off, short lenOff) {
		setLength3(buf, (short)(lenOff - 3), (short)(off - lenOff));
	}

	public static void setPreparedLength2(byte[] buf, short off, short lenOff) {
		setLength2(buf, (short)(lenOff - 2), (short)(off - lenOff));
	}

	public static void setPreparedLength1(byte[] buf, short off, short lenOff) {
		setLength1(buf, (short)(lenOff - 1), (short)(off - lenOff));
	}

	public static short setTag(byte[] buf, short off, short tag) {
		if (tag >= 256)
			off = Util.setShort(buf, off, tag);
		else
			buf[off++] = (byte)tag;
		return off;
	}

	public static short zeroByteArray(byte[] array) {
		return Util.arrayFillNonAtomic(array, (short)0, (short)array.length, (byte)0);
	}

	public void incrementDigitalSignatureCounter() {
		byte[] dsc = digitalSignatureCounter;
		boolean needTransaction = JCSystem.getTransactionDepth() == 0;

		if (needTransaction)
			JCSystem.beginTransaction();

		if (dsc[1] == 0xff && dsc[2] == 0xff)
			dsc[0]++;
		if (dsc[2] == 0xff)
			dsc[1]++;
		dsc[2]++;

		if (needTransaction)
			JCSystem.commitTransaction();
	}

	public short getDigitalSignatureCounter(byte[] buf, short off) {
		return Util.arrayCopyNonAtomic(digitalSignatureCounter, (short)0, buf, off, (short)digitalSignatureCounter.length);
	}

	public void reset() {
		userPIN.clear();
		userPUK.clear();
		adminPIN.clear();

		name.clear();
		language.clear();
		sex.clear();
		url.clear();
		login.clear();
		for (byte i = 0; i < caFingerprints.length; i++)
			caFingerprints[i].clear();

		signatureKeyStore.clear();
		decryptionKeyStore.clear();
		authenticationKeyStore.clear();
		zeroByteArray(digitalSignatureCounter);

		/* keep last, so we don't have to use transactions */
		cardTerminated = false;
	}

	public void process(APDU apdu) {
		byte[] buf = apdu.getBuffer();
		byte cla = buf[ISO7816.OFFSET_CLA];
		byte ins = buf[ISO7816.OFFSET_INS];

		if (selectingApplet()) {
			if (cardTerminated)
				ISOException.throwIt(SW_TERMINATED);
			return;
		}

		if (apdu.isSecureMessagingCLA())
			ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);

		if (apdu.isCommandChainingCLA())
			ISOException.throwIt(ISO7816.SW_COMMAND_CHAINING_NOT_SUPPORTED);

		if (cla != 0)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

		if (cardTerminated) {
			switch (ins) {
			case INS_ACTIVATE_FILE:
				processActivateFile(apdu);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
				break;
			}

			return;
		}

		switch (ins) {
		//case ISO7816.INS_SELECT:
		case INS_SELECT_DATA:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			break;
		case INS_GET_DATA:
			processGetData(apdu);
			break;
		case INS_GET_NEXT_DATA:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			break;
		case INS_VERIFY:
			processVerify(apdu);
			break;
		case INS_CHANGE_REFERENCE_DATA:
			processChangeReferenceData(apdu);
			break;
		case INS_RESET_RETRY_COUNTER:
			processResetRetryCounter(apdu);
			break;
		case INS_PUT_DATA:
			processPutData(apdu);
			break;
		case INS_IMPORT_KEY:
			processImportKey(apdu);
			break;
		case INS_GENERATE_ASYMMETRIC_KEY_PAIR:
			processGenerateAsymmetricKeyPair(apdu);
			break;
		case INS_PERFORM_SECURITY_OPERATION:
			processPerformSecurityOperation(apdu);
			break;
		case INS_INTERNAL_AUTHENTICATE:
			processInternalAuthenticate(apdu);
			break;
		case INS_GET_RESPONSE:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			break;
		case INS_GET_CHALLENGE:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			break;
		case INS_TERMINATE_DF:
			processTerminateDF(apdu);
			break;
		case INS_ACTIVATE_FILE:
			break;
		case INS_MANAGE_SECURITY_ENVIRONMENT:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			break;
		}
	}

	private short getHistoricalBytes(byte[] buf, short off) {
		byte tmp;

		buf[off++] = (byte)0x00;

		/* cTLV 0x73 */
		buf[off++] = (byte)0x73;
		buf[off++] = (byte)0x00;
		buf[off++] = (byte)0x00;

		tmp = (byte)(0 << 7) | /* Command chaining supported */
			(byte)(0 << 5) | /* Extended length info in EF.ATR */
			(byte)(0 << 3) | /* Logical channel number */
			(byte)(0 << 0);  /* Maximal logical channels */

		/* Extended length supported */
		if (tmpBuffer != null)
			tmp |= (byte)(1 << 6);
		buf[off++] = tmp;

		/* cTLV 0x31 */
		buf[off++] = (byte)0x31;
		buf[off++] = (byte)0xde;

		/* LCS */
		if (cardTerminated)
			buf[off++] = (byte)0x03;
		else
			buf[off++] = (byte)0x05;
		buf[off++] = (byte)0x90;
		buf[off++] = (byte)0x00;

		return off;
	};

	private short getExtendedLengthInformation(byte[] buf, short off) {
		short lengthOffset1, lengthOffset2;

		off = setTag(buf, off, TAG_EXTENDED_LENGTH_INFORMATION);
		off = lengthOffset1 = prepareLength1(buf, off);
		off = setTag(buf, off, (short)0x02);
		off = lengthOffset2 = prepareLength1(buf, off);
		off = Util.setShort(buf, off, (short)0x400);
		setPreparedLength1(buf, off, lengthOffset2);
		off = setTag(buf, off, (short)0x02);
		off = lengthOffset2 = prepareLength1(buf, off);
		off = Util.setShort(buf, off, (short)0x400);
		setPreparedLength1(buf, off, lengthOffset2);
		setPreparedLength1(buf, off, lengthOffset1);

		return off;
	}

	private short getPWStatusBytes(byte[] buf, short off) {
		buf[off++] = (byte)0x01;
		buf[off++] = NeoPIN.MAX_LENGTH;
		buf[off++] = NeoPIN.MAX_LENGTH;
		buf[off++] = NeoPIN.MAX_LENGTH;
		buf[off++] = userPIN.getTriesRemaining();
		buf[off++] = userPUK.getTriesRemaining();
		buf[off++] = adminPIN.getTriesRemaining();

		return off;
	}

	private short getExtendedCapabilities(byte[] buf, short off) {
		/* exteded capabilites */
		buf[off++] =
			(byte)(0 << 7) | /* SM supported */
			(byte)(0 << 6) | /* GET_CHALLENGE supported */
			(byte)(1 << 5) | /* Key import supported  */
			(byte)(0 << 4) | /* PW status changeable */
			(byte)(0 << 3) | /* Private use DOs supported */
			(byte)(1 << 2) | /* Algorithm attributes changable */
			(byte)(0 << 1) | /* ENC/DEC with AES supported */
			(byte)(0 << 0);  /* KDF supported */

		/* SM algorithm */
		buf[off++] = (byte)0x00;

		/* Max length for GET CHALLENGE */
		off = Util.setShort(buf, off, (short)0);

		/* Max length of cardholder certificates */
		off = Util.setShort(buf, off, (short)0);

		/* Max length of special DOs */
		off = Util.setShort(buf, off, SPECIAL_DO_MAX_LENGTH);

		/* PIN block 2 format */
		buf[off++] = (byte)0x00;

		/* MSE command for decryption and authentication key */
		buf[off++] = (byte)0x00;

		return off;
	}

	private short getSecuritySupportTemplate(byte[] buf, short off) {
		short lengthOffset1, lengthOffset2;

		off = setTag(buf, off, TAG_SECURITY_SUPPORT_TEMPLATE);
		off = lengthOffset1 = prepareLength1(buf, off);
		off = setTag(buf, off, TAG_DIGITAL_SIGNATURE_COUNTER);
		off = lengthOffset2 = prepareLength1(buf, off);
		off = getDigitalSignatureCounter(buf, off);
		setPreparedLength1(buf, off, lengthOffset2);
		setPreparedLength1(buf, off, lengthOffset1);

		return off;
	}

	private short getKeyInformation(byte[] buf, short off) {
		off = NeoKey.SIGNATURE_KEY;
		off = signatureKey.getStatus(buf, off);
		off = NeoKey.DECRYPTION_KEY;
		off = decryptionKey.getStatus(buf, off);
		off = NeoKey.AUTHENTICATION_KEY;
		off = authenticationKey.getStatus(buf, off);

		return off;
	}

	private short getApplicationRelatedData(byte[] buf, short off) {
		short lengthOffset1, lengthOffset2, lengthOffset3;

		off = setTag(buf, off, TAG_APPLICATION_RELATED_DATA);
		off = lengthOffset1 = prepareLength1(buf, off);
		off = setTag(buf, off, TAG_DISCRETIONARY_DATA_OBJECTS);
		off = lengthOffset2 = prepareLength1(buf, off);
		off = setTag(buf, off, TAG_EXTENDED_CAPABILITIES);
		off = lengthOffset3 = prepareLength1(buf, off);
		off = getExtendedCapabilities(buf, off);
		setPreparedLength1(buf, off, lengthOffset3);
		off = setTag(buf, off, TAG_ALGORITHM_ATTRIBUTES_SIGNATURE);
		off = lengthOffset3 = prepareLength1(buf, off);
		off = signatureKey.getAlgorithmAttributes(buf, off);
		setPreparedLength1(buf, off, lengthOffset3);
		off = setTag(buf, off, TAG_ALGORITHM_ATTRIBUTES_DECRYPTION);
		off = lengthOffset3 = prepareLength1(buf, off);
		off = decryptionKey.getAlgorithmAttributes(buf, off);
		setPreparedLength1(buf, off, lengthOffset3);
		off = setTag(buf, off, TAG_ALGORITHM_ATTRIBUTES_AUTHENTICATION);
		off = lengthOffset3 = prepareLength1(buf, off);
		off = authenticationKey.getAlgorithmAttributes(buf, off);
		setPreparedLength1(buf, off, lengthOffset3);
		off = setTag(buf, off, TAG_KEY_FINGERPRINTS);
		off = lengthOffset3 = prepareLength1(buf, off);
		off = signatureKey.getFingerprint(buf, off);
		off = decryptionKey.getFingerprint(buf, off);
		off = authenticationKey.getFingerprint(buf, off);
		setPreparedLength1(buf, off, lengthOffset3);
		setPreparedLength1(buf, off, lengthOffset2);
		setPreparedLength1(buf, off, lengthOffset1);

		return off;
	}

	private short getCardholderRelatedData(byte[] buf, short off) {
		short lengthOffset1, lengthOffset2;

		off = setTag(buf, off, TAG_CARDHOLDER_RELATED_DATA);
		off = lengthOffset1 = prepareLength1(buf, off);

		off = setTag(buf, off, TAG_NAME);
		off = lengthOffset2 = prepareLength1(buf, off);
		off = name.get(buf, off);
		setPreparedLength1(buf, off, lengthOffset2);

		off = setTag(buf, off, TAG_LANGUAGE);
		off = lengthOffset2 = prepareLength1(buf, off);
		off = language.get(buf, off);
		setPreparedLength1(buf, off, lengthOffset2);

		off = setTag(buf, off, TAG_SEX);
		off = lengthOffset2 = prepareLength1(buf, off);
		off = sex.get(buf, off);
		setPreparedLength1(buf, off, lengthOffset2);
		setPreparedLength1(buf, off, lengthOffset1);

		return off;
	}

	private short getAlgorithmInformation(byte[] buf, short off) {
		short lengthOffset;

		off = setTag(buf, off, TAG_ALGORITHM_INFORMATION);
		off = lengthOffset = prepareLength2(buf, off);
		off = signatureKeyStore.getAllAlgorithmAttributes(buf, off);
		off = decryptionKeyStore.getAllAlgorithmAttributes(buf, off);
		off = authenticationKeyStore.getAllAlgorithmAttributes(buf, off);
		setPreparedLength2(buf, off, lengthOffset);

		return off;
	}


	private void processGetData(APDU apdu) throws ISOException {
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short tag = Util.makeShort(p1, p2);
		short off = 0;

		switch (tag) {
		case TAG_AID:
			off = JCSystem.getAID().getBytes(buf, off);
			break;
		case TAG_APPLICATION_RELATED_DATA:
			off = getApplicationRelatedData(buf, off);
			break;
		case TAG_CARDHOLDER_RELATED_DATA:
			off = getCardholderRelatedData(buf, off);
			break;
		case TAG_HISTORICAL_BYTES:
			off = getHistoricalBytes(buf, off);
			break;
		case TAG_EXTENDED_LENGTH_INFORMATION:
			off = getExtendedLengthInformation(buf, off);
			break;
		case TAG_PW_STATUS_BYTES:
			off = getPWStatusBytes(buf, off);
			break;
		case TAG_EXTENDED_CAPABILITIES:
			off = getExtendedCapabilities(buf, off);
			break;
		case TAG_ALGORITHM_ATTRIBUTES_SIGNATURE:
			off = signatureKey.getAlgorithmAttributes(buf, off);
			break;
		case TAG_ALGORITHM_ATTRIBUTES_DECRYPTION:
			off = decryptionKey.getAlgorithmAttributes(buf, off);
			break;
		case TAG_ALGORITHM_ATTRIBUTES_AUTHENTICATION:
			off = authenticationKey.getAlgorithmAttributes(buf, off);
			break;
		case TAG_NAME:
			off = name.get(buf, off);
			break;
		case TAG_LANGUAGE:
			off = language.get(buf, off);
			break;
		case TAG_SEX:
			off = sex.get(buf, off);
			break;
		case TAG_URL:
			off = url.get(buf, off);
			break;
		case TAG_LOGIN:
			off = login.get(buf, off);
			break;
		case TAG_KEY_FINGERPRINTS:
			off = signatureKey.getFingerprint(buf, off);
			off = decryptionKey.getFingerprint(buf, off);
			off = authenticationKey.getFingerprint(buf, off);
			break;
		case TAG_KEY_GENERATION_TIMESTAMP:
			off = signatureKey.getTimestamp(buf, off);
			off = decryptionKey.getTimestamp(buf, off);
			off = authenticationKey.getTimestamp(buf, off);
			break;
		case TAG_CA_FINGERPRINTS:
			off = caFingerprints[0].get(buf, off);
			off = caFingerprints[1].get(buf, off);
			off = caFingerprints[2].get(buf, off);
			break;
		case TAG_SIGNATURE_KEY_FINGERPRINT:
			off = signatureKey.getFingerprint(buf, off);
			break;
		case TAG_DECRYPTION_KEY_FINGERPRINT:
			off = decryptionKey.getFingerprint(buf, off);
			break;
		case TAG_AUTHENTICATION_KEY_FINGERPRINT:
			off = authenticationKey.getFingerprint(buf, off);
			break;
		case TAG_SIGNATURE_KEY_TIMESTAMP:
			off = signatureKey.getTimestamp(buf, off);
			break;
		case TAG_DECRYPTION_KEY_TIMESTAMP:
			off = decryptionKey.getTimestamp(buf, off);
			break;
		case TAG_AUTHENTICATION_KEY_TIMESTAMP:
			off = authenticationKey.getTimestamp(buf, off);
			break;
		case TAG_CA1_FINGERPRINT:
			off = caFingerprints[0].get(buf, off);
			break;
		case TAG_CA2_FINGERPRINT:
			off = caFingerprints[1].get(buf, off);
			break;
		case TAG_CA3_FINGERPRINT:
			off = caFingerprints[2].get(buf, off);
			break;
		case TAG_SECURITY_SUPPORT_TEMPLATE:
			off = getSecuritySupportTemplate(buf, off);
			break;
		case TAG_DIGITAL_SIGNATURE_COUNTER:
			off = getDigitalSignatureCounter(buf, off);
			break;
		case TAG_KEY_INFORMATION:
			off = getKeyInformation(buf, off);
			break;
		case TAG_ALGORITHM_INFORMATION:
			off = getAlgorithmInformation(buf, off);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			break;
		}

		apdu.setOutgoingAndSend((short)0, off);
	}

	private void processPutData(APDU apdu) throws ISOException {
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short tag = Util.makeShort(p1, p2);
		short lc;
		short off = 0;

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		off = apdu.getOffsetCdata();

		switch (tag) {
		case TAG_NAME:
			adminPIN.assertValidated();
			name.set(buf, off, lc);
			break;
		case TAG_LOGIN:
			adminPIN.assertValidated();
			login.set(buf, off, lc);
			break;
		case TAG_LANGUAGE:
			adminPIN.assertValidated();
			language.set(buf, off, lc);
			break;
		case TAG_SEX:
			adminPIN.assertValidated();
			sex.set(buf, off, lc);
			break;
		case TAG_URL:
			adminPIN.assertValidated();
			url.set(buf, off, lc);
			break;
		case TAG_KEY_FINGERPRINTS:
			adminPIN.assertValidated();
			if (lc != 3 * FINGERPRINT_LENGTH)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			off = signatureKey.setFingerprint(buf, off, FINGERPRINT_LENGTH);
			off = decryptionKey.setFingerprint(buf, off, FINGERPRINT_LENGTH);
			off = authenticationKey.setFingerprint(buf, off, FINGERPRINT_LENGTH);
			break;
		case TAG_SIGNATURE_KEY_FINGERPRINT:
			adminPIN.assertValidated();
			off = signatureKey.setFingerprint(buf, off, lc);
			break;
		case TAG_DECRYPTION_KEY_FINGERPRINT:
			adminPIN.assertValidated();
			off = decryptionKey.setFingerprint(buf, off, lc);
			break;
		case TAG_AUTHENTICATION_KEY_FINGERPRINT:
			adminPIN.assertValidated();
			off = authenticationKey.setFingerprint(buf, off, lc);
			break;
		case TAG_KEY_GENERATION_TIMESTAMP:
			adminPIN.assertValidated();
			if (lc != 3 * TIMESTAMP_LENGTH)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			off = signatureKey.setTimestamp(buf, off, TIMESTAMP_LENGTH);
			off = decryptionKey.setTimestamp(buf, off, TIMESTAMP_LENGTH);
			off = authenticationKey.setTimestamp(buf, off, TIMESTAMP_LENGTH);
			break;
		case TAG_SIGNATURE_KEY_TIMESTAMP:
			adminPIN.assertValidated();
			off = signatureKey.setTimestamp(buf, off, lc);
			break;
		case TAG_DECRYPTION_KEY_TIMESTAMP:
			adminPIN.assertValidated();
			off = decryptionKey.setTimestamp(buf, off, lc);
			break;
		case TAG_AUTHENTICATION_KEY_TIMESTAMP:
			adminPIN.assertValidated();
			off = authenticationKey.setTimestamp(buf, off, lc);
			break;
		case TAG_CA_FINGERPRINTS:
			adminPIN.assertValidated();
			if (lc != 3 * FINGERPRINT_LENGTH)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			off = caFingerprints[0].set(buf, off, FINGERPRINT_LENGTH);
			off = caFingerprints[1].set(buf, off, FINGERPRINT_LENGTH);
			off = caFingerprints[2].set(buf, off, FINGERPRINT_LENGTH);
			break;
		case TAG_CA1_FINGERPRINT:
			adminPIN.assertValidated();
			off = caFingerprints[0].set(buf, off, lc);
			break;
		case TAG_CA2_FINGERPRINT:
			adminPIN.assertValidated();
			off = caFingerprints[1].set(buf, off, lc);
			break;
		case TAG_CA3_FINGERPRINT:
			adminPIN.assertValidated();
			off = caFingerprints[2].set(buf, off, lc);
			break;
		case TAG_RESET_CODE:
			adminPIN.assertValidated();
			if (lc != 0)
				userPUK.update(buf, off, lc);
			else
				userPUK.clear();
			break;
		case TAG_ALGORITHM_ATTRIBUTES_SIGNATURE:
			adminPIN.assertValidated();
			{
				NeoKey newKey;
				newKey = signatureKeyStore.setAlgorithmAttributes(buf, off, lc);
				if (newKey == null)
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				JCSystem.beginTransaction();
				signatureKey.clear();
				signatureKey = newKey;
				JCSystem.commitTransaction();
			} break;
		case TAG_ALGORITHM_ATTRIBUTES_DECRYPTION:
			adminPIN.assertValidated();
			{
				NeoKey newKey;
				newKey = decryptionKeyStore.setAlgorithmAttributes(buf, off, lc);
				if (newKey == null)
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				JCSystem.beginTransaction();
				decryptionKey.clear();
				decryptionKey = newKey;
				JCSystem.commitTransaction();
			} break;
		case TAG_ALGORITHM_ATTRIBUTES_AUTHENTICATION:
			adminPIN.assertValidated();
			{
				NeoKey newKey;
				newKey = authenticationKeyStore.setAlgorithmAttributes(buf, off, lc);
				if (newKey == null)
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				JCSystem.beginTransaction();
				authenticationKey.clear();
				authenticationKey = newKey;
				JCSystem.commitTransaction();
			} break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			break;
		}
	}

	private void processChangeReferenceData(APDU apdu) throws ISOException {
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short lc, off;
		NeoPIN pin;

		if (p1 != 0)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		off = apdu.getOffsetCdata();

		switch (p2) {
		case CHANGE_REFERENCE_DATA_P2_PW1:
			pin = userPIN;
			break;
		case CHANGE_REFERENCE_DATA_P2_PW3:
			pin = adminPIN;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			return;
		}

		pin.change(buf, off, lc);
	}

	private void processResetRetryCounter(APDU apdu) throws ISOException {
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short lc, off, len;

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		off = apdu.getOffsetCdata();

		if (p2 != RESET_RETRY_COUNTER_P2_PW1)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);

		switch (p1) {
		case RESET_RETRY_COUNTER_P1_BY_PW3:
			adminPIN.assertValidated();
			userPIN.update(buf, off, lc);
			break;
		case RESET_RETRY_COUNTER_P1_BY_RC:
			userPIN.change(buf, off, lc, userPUK);
			break;
		}
	}

	private void processVerify(APDU apdu) throws ISOException {
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short lc, off;
		NeoPIN pin;
		byte mode = NeoPIN.MODE_NONE;

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		off = apdu.getOffsetCdata();

		switch (p2) {
		case VERIFY_P2_PW1_CDS:
			pin = userPIN;
			mode = USER_PIN_MODE_CDS;
			break;
		case VERIFY_P2_PW1:
			pin = userPIN;
			mode = USER_PIN_MODE_NORMAL;
			break;
		case VERIFY_P2_PW3:
			pin = adminPIN;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			return;
		}

		switch (p1) {
		case VERIFY_P1_CHECK:
			if (lc != 0) {
				if (!pin.check(buf, off, (byte)lc, mode))
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			} else {
				if (!pin.isValidated(mode))
					ISOException.throwIt((short)(0x63c0 | pin.getTriesRemaining()));
			}
			break;
		case VERIFY_P1_RESET:
			if (lc != 0)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

			pin.reset(mode);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			return;
		}
	}

	private void processActivateFile(APDU apdu) throws ISOException {
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];

		if (p1 != 0 || p2 != 0)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);

		reset();
	}

	private void processTerminateDF(APDU apdu) throws ISOException {
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];

		if (p1 != 0 || p2 != 0)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);

		/*
		 * According to the specification, if the PIN is blocked,
		 * the card can be terminated anyway.
		 *
		 * That doesn't make much sense, because one could just try
		 * to authenticate as an admin three times in a row and then
		 * terminate the card without knowing the admin PIN.
		 */
		if (adminPIN.getTriesRemaining() != 0)
			adminPIN.assertValidated();

		cardTerminated = true;
	}

	private void processGenerateAsymmetricKeyPair(APDU apdu) throws ISOException {
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short lc, off;
		NeoKey key;

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		if (lc != 2 && lc != 5)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		if (p2 != 0)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);

		off = apdu.getOffsetCdata();

		switch (buf[off]) {
		case GENKEY_CRT_SIGNATURE_KEY:
			key = signatureKey;
			break;
		case GENKEY_CRT_DECRYPTION_KEY:
			key = decryptionKey;
			break;
		case GENKEY_CRT_AUTHENTICATION_KEY:
			key = authenticationKey;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		switch (p1) {
		case GENKEY_P1_GENERATE:
			adminPIN.assertValidated();

			/*
			 * Some cards (e.g. ACOSJ) doesn't support transaction
			 * during key generation.
			 */
			if (!hasConfiguration(CFG_NO_KEYGEN_TRANSACTION))
				JCSystem.beginTransaction();

			key.generateKey();

			/* Protect at least the signature counter. */
			if (hasConfiguration(CFG_NO_KEYGEN_TRANSACTION))
				JCSystem.beginTransaction();

			if (key == signatureKey)
				zeroByteArray(digitalSignatureCounter);
			JCSystem.commitTransaction();
			break;
		case GENKEY_P1_READ_PUBLICKEY:
			break;
		default:
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			break;
		}

		if (tmpBuffer != null)
			buf = tmpBuffer;

		off = key.getPublicKey(buf, (short)0);

		if (tmpBuffer != null) {
			apdu.setOutgoing();
			apdu.setOutgoingLength(off);
			apdu.sendBytesLong(buf, (short)0, off);
		} else {
			apdu.setOutgoingAndSend((short)0, off);
		}
	}

	private void processPerformSecurityOperation(APDU apdu) throws ISOException {
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short op = Util.makeShort(p1, p2);
		short lc, off;

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		off = apdu.getOffsetCdata();

		switch (op) {
		case PSO_OP_COMPUTE_DIGITAL_SIGNATURE:
			userPIN.isValidated(USER_PIN_MODE_CDS);
			incrementDigitalSignatureCounter();
			off = signatureKey.sign(buf, off, lc);
			break;
		case PSO_OP_DECIPHER:
			userPIN.isValidated(USER_PIN_MODE_NORMAL);
			off = decryptionKey.decipher(buf, off, lc);
			break;
		case PSO_OP_ENCIPHER:
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			break;
		}

		apdu.setOutgoingAndSend((short)0, off);
	}

	private void processInternalAuthenticate(APDU apdu) throws ISOException {
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short lc, off;

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		off = apdu.getOffsetCdata();

		if (p1 != 0 || p2 != 0)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);

		userPIN.isValidated(USER_PIN_MODE_NORMAL);
		off = authenticationKey.authenticate(buf, off, lc);
		apdu.setOutgoingAndSend((short)0, off);
	}

	private void processImportKey(APDU apdu) throws ISOException {
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short tag = Util.makeShort(p1, p2);
		short len, lc, off, tlv;

		if (p1 != (byte)0x3f || p2 != (byte)0xff)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);

		len = apdu.setIncomingAndReceive();
		lc = apdu.getIncomingLength();
		off = apdu.getOffsetCdata();

		if (tmpBuffer != null) {
			short pos = 0;
			do {
				Util.arrayCopyNonAtomic(buf, off, tmpBuffer, pos, len);
				pos += len;
			} while ((len = apdu.receiveBytes(off)) != (short)0);
			off = (short)0;
			len = pos;
			buf = tmpBuffer;
		}

		if (len != lc)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		adminPIN.assertValidated();

		if (buf[off] != (byte)TAG_EXTENDED_HEADER_LIST)
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);

		JCSystem.beginTransaction();
		if (NeoBERParser.find(buf, off, BER_TAG_SIGNATURE_KEY, (short)0) >= (short)0) {
			zeroByteArray(digitalSignatureCounter);
			signatureKey.importKey(buf, off, lc);
		} else if (NeoBERParser.find(buf, off, BER_TAG_DECRYPTION_KEY, (short)0) >= (short)0) {
			decryptionKey.importKey(buf, off, lc);
		} else if (NeoBERParser.find(buf, off, BER_TAG_AUTHENTICATION_KEY, (short)0) >= (short)0) {
			authenticationKey.importKey(buf, off, lc);
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		JCSystem.commitTransaction();
	}
}
