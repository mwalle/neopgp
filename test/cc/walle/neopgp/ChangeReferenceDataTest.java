// SPDX-License-Identifier: GPL-3.0-or-later
package cc.walle.neopgp;

import static org.junit.Assert.*;
import javax.smartcardio.ResponseAPDU;
import javacard.framework.ISO7816;
import org.junit.Test;

public class ChangeReferenceDataTest extends JcardsimTestCase {
	@Test public void changeUserPIN() {
		assertResponseOK("002400810D31323334353631323334353637");
	}

	@Test public void changeUserPINToLongAndTryShortOne() {
		assertResponseOK("002400811D3132333435363132333435363738394041424344454647484950515253");
		assertResponseStatus(0x6982, "002400810C313233343536313233343536");
	}
}
