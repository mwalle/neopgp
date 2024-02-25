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
}
