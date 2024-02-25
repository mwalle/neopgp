// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import static org.junit.Assert.*;
import javax.smartcardio.ResponseAPDU;
import org.junit.Test;

public class VerifyTest extends JcardsimTestCase {
	@Test public void defaultUserPIN() {
		assertResponseStatus(0x9000, "0020008106313233343536");
	}

	@Test public void defaultUserCDSPIN() {
		assertResponseStatus(0x9000, "0020008206313233343536");
	}

	@Test public void defaultAdminPIN() {
		assertResponseStatus(0x9000, "00200083083132333435363738");
	}

	@Test public void defaultUserPINTries() {
		assertResponseStatus(0x63c3, "0020008100");
	}

	@Test public void defaultUserCDSPINTries() {
		assertResponseStatus(0x63c3, "0020008200");
	}

	@Test public void defaultAdminPINTries() {
		assertResponseStatus(0x63c3, "0020008300");
	}
}
