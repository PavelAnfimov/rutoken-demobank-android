package ru.rutoken.demobank;

import org.spongycastle.asn1.x500.RDN;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x500.style.BCStyle;
import org.spongycastle.asn1.x500.style.IETFUtils;

class Utils {
    static String commonNameFromX500Name(X500Name name) {
        String commonName = "";
        RDN[] rdns = name.getRDNs(BCStyle.CN);
        if (rdns == null || rdns.length == 0)
            return commonName;
        commonName = IETFUtils.valueToString(rdns[0].getFirst().getValue());
        return commonName;
    }
}
