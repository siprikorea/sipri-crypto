package com.siprikorea.crypto.jcajce.provider.eckcdsa;

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.ECParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

/**
 * One EC-KCDSA domain in its three representations: the X9.62 ASN.1 parameters used in
 * encodings (a named curve OID where one exists), the lightweight domain parameters used by the
 * signer, and the JCA {@link ECParameterSpec}.
 */
final class ECKCDSADomain
{
    final X962Parameters asn1;
    final ECDomainParameters domain;
    final ECParameterSpec spec;

    private ECKCDSADomain(X962Parameters asn1, X9ECParameters x9, ECParameterSpec spec)
    {
        this.asn1 = asn1;
        this.domain = new ECDomainParameters(x9);
        this.spec = spec;
    }

    static ECKCDSADomain fromName(String name)
        throws InvalidAlgorithmParameterException
    {
        ASN1ObjectIdentifier oid = ECUtil.getNamedCurveOid(name);
        if (oid == null)
        {
            throw new InvalidAlgorithmParameterException("unknown curve name: " + name);
        }
        return fromOid(oid);
    }

    static ECKCDSADomain fromOid(ASN1ObjectIdentifier oid)
        throws InvalidAlgorithmParameterException
    {
        X9ECParameters x9 = ECUtil.getNamedCurveByOid(oid);
        if (x9 == null)
        {
            throw new InvalidAlgorithmParameterException("unknown curve OID: " + oid);
        }

        ECParameterSpec spec = new ECNamedCurveSpec(ECUtil.getCurveName(oid),
            EC5Util.convertCurve(x9.getCurve(), x9.getSeed()), EC5Util.convertPoint(x9.getG()), x9.getN(), x9.getH());

        return new ECKCDSADomain(new X962Parameters(oid), x9, spec);
    }

    static ECKCDSADomain fromAsn1(X962Parameters params)
        throws InvalidAlgorithmParameterException
    {
        if (params.isNamedCurve())
        {
            return fromOid(ASN1ObjectIdentifier.getInstance(params.getParameters()));
        }
        if (params.isImplicitlyCA())
        {
            throw new InvalidAlgorithmParameterException("implicitlyCA EC-KCDSA parameters are not supported");
        }

        X9ECParameters x9 = X9ECParameters.getInstance(params.getParameters());
        return new ECKCDSADomain(params, x9, EC5Util.convertToSpec(x9));
    }

    static ECKCDSADomain fromSpec(ECParameterSpec spec)
        throws InvalidAlgorithmParameterException
    {
        if (spec instanceof ECNamedCurveSpec)
        {
            return fromName(((ECNamedCurveSpec)spec).getName());
        }

        org.bouncycastle.jce.spec.ECParameterSpec bcSpec = EC5Util.convertSpec(spec);
        ASN1ObjectIdentifier oid = ECUtil.getNamedCurveOid(bcSpec);
        if (oid != null)
        {
            return fromOid(oid);
        }

        X9ECParameters x9 = new X9ECParameters(bcSpec.getCurve(), new X9ECPoint(bcSpec.getG(), false),
            bcSpec.getN(), bcSpec.getH(), bcSpec.getSeed());
        return new ECKCDSADomain(new X962Parameters(x9), x9, spec);
    }
}
