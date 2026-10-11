package com.siprikorea.crypto.asn1;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Object identifiers for the Korean algorithms supported by Sipri Crypto.
 */
public interface SipriObjectIdentifiers
{
    /**
     * ISO/IEC 14888-3 KCDSA public key:
     * {iso(1) standard(0) digital-signature-with-appendix(14888) part3(3) algorithm(0) kcdsa(2)}
     */
    ASN1ObjectIdentifier kcdsa = new ASN1ObjectIdentifier("1.0.14888.3.0.2");

    /**
     * ISO/IEC 14888-3 EC-KCDSA public key:
     * {iso(1) standard(0) digital-signature-with-appendix(14888) part3(3) algorithm(0) ec-kcdsa(5)}
     */
    ASN1ObjectIdentifier ecKcdsa = new ASN1ObjectIdentifier("1.0.14888.3.0.5");

    /**
     * KCDSA public key as used in the Korean e-Government PKI (eGOV-C01.0008), accepted on input.
     */
    ASN1ObjectIdentifier kcdsa_kisa = new ASN1ObjectIdentifier("1.2.410.200004.1.1");

    /**
     * EC-KCDSA public key as used in the Korean e-Government PKI (eGOV-C01.0008), accepted on input.
     */
    ASN1ObjectIdentifier ecKcdsa_kisa = new ASN1ObjectIdentifier("1.2.410.200004.1.100.2.1");
}
