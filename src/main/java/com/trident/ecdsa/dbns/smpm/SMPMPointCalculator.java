/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.trident.ecdsa.dbns.smpm;

import com.trident.crypto.elliptic.EllipticCurveOperator;
import com.trident.crypto.elliptic.EllipticCurvePoint;
import java.math.BigInteger;
import java.util.Map;
import java.util.TreeMap;

/**
 *
 * @author trident
 */
public class SMPMPointCalculator {
    private Map<BigInteger,Map<BigInteger,EllipticCurvePoint>> values;
    private final EllipticCurveOperator operator;
    private final EllipticCurvePoint P;
    private final EllipticCurvePoint Q;
    private final int omega;
    
    public SMPMPointCalculator(int omega, EllipticCurveOperator operator, EllipticCurvePoint P, EllipticCurvePoint Q){
        this.omega = omega;
        this.operator = operator;
        this.P = P;
        this.Q = Q;
    }

    public Map<BigInteger, Map<BigInteger, EllipticCurvePoint>> calculateValues() {
        if(values == null)
            calculatePoints();
        return values;
    }

    public int getOmega() {
        return omega;
    }
    
    protected void calculatePoints(){
        values = new TreeMap<>();
        BigInteger size = BigInteger.ONE.shiftLeft(omega); // 2^omega
        
        for(BigInteger i = BigInteger.ZERO; i.compareTo(size)<0; i.add(BigInteger.ONE)){
            values.put(i, new TreeMap<>());
            for(BigInteger j = BigInteger.ZERO; j.compareTo(size)<0; j.add(BigInteger.ONE)){
                values.get(i).put(j, operator.add(operator.mul(i, P), operator.mul(j, Q)));
            }
        }
    }
    
    
}
