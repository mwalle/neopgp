// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import static org.junit.Assert.*;
import javax.smartcardio.ResponseAPDU;
import javacard.framework.ISO7816;
import org.junit.Test;

public class PutDataTest extends JcardsimTestCase {
	@Test public void nameWithoutAuth() {
		assertResponseStatus(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, "00DA005B0548656C6C6F");
		assertResponseData("" , "00CA005B00");
	}

	@Test public void nameWithAuth() {
		admin();
		assertResponseOK("00DA005B0548656C6C6F");
		assertResponseData("48656C6C6F" , "00CA005B00");
	}

	@Test public void nameWithUserAuth() {
		assertResponseOK("0020008106313233343536");
		assertResponseStatus(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, "00DA005B0548656C6C6F");
		assertResponseOK("0020008206313233343536");
		assertResponseStatus(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, "00DA005B0548656C6C6F");
	}

	@Test public void fingerprintWrongLength() {
		admin();
		assertResponseStatus(ISO7816.SW_WRONG_LENGTH, "00DA00C70100");
	}

	@Test public void fingerprint() {
		admin();
		assertResponseOK("00DA00C71400112233445566778899AABBCCDDEEFF00112233");
	}

	@Test public void decryptionFingerprintSetAndGet() {
		admin();
		assertResponseOK("00DA00C81400112233445566778899AABBCCDDEEFF00112233");
		assertResponseData("000000000000000000000000000000000000000000112233445566778899AABBCCDDEEFF001122330000000000000000000000000000000000000000" , "00CA00C500");
	}

	@Test public void privateDO0101() {
		user();
		assertResponseOK("00DA010108001122334455667788");
	}

	@Test public void privateDO0102() {
		admin();
		assertResponseOK("00DA010208001122334455667788");
	}

	@Test public void privateDO0103() {
		user();
		assertResponseOK("00DA010308001122334455667788");
	}

	@Test public void privateDO0104() {
		admin();
		assertResponseOK("00DA010408001122334455667788");
	}
}
