/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.trident.ecdsa.dbns.smpm;

import com.trident.crypto.elliptic.EllipticCurvePoint;
import com.trident.crypto.util.Tuple;
import java.math.BigInteger;
import java.util.Map;

/**
 *
 * @author trident
 */
public class SMPMContainerImpl implements SMPMContainer{
    
    private final Map<BigInteger,Map<BigInteger,EllipticCurvePoint>> values;
    private final int omega;
    private final Tuple<EllipticCurvePoint,EllipticCurvePoint> declaredPoints;

    public SMPMContainerImpl(Map<BigInteger, Map<BigInteger, EllipticCurvePoint>> values, Tuple<EllipticCurvePoint, EllipticCurvePoint> declaredPoints, int omega) {
        this.values = values;
        this.declaredPoints = declaredPoints;
        this.omega = omega;
    }
    
    @Override
    public EllipticCurvePoint get(BigInteger i, BigInteger j) {
        return values.get(i)!=null?values.get(i).get(j):null;
    }

    @Override
    public int getOmega() {
        return omega;
    }

    @Override
    public Tuple<EllipticCurvePoint, EllipticCurvePoint> getPoints() {
        return declaredPoints;
    }

    @Override
    public Map<BigInteger, Map<BigInteger, EllipticCurvePoint>> getAll() {
        return values;
    }
    
}
