/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.trident.ecdsa.dbns.smpm;

import com.trident.crypto.algo.mpmbehavior.MPMBehavior;
import com.trident.crypto.elliptic.EllipticCurveOperator;
import com.trident.crypto.elliptic.EllipticCurvePoint;
import com.trident.crypto.util.Tuple;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author trident
 */
public class SMPMBehavior implements MPMBehavior{
    
    /**
     * storage of pre-calculated points
     */
    private final SMPMContainer container;
    
    /**
     * operator over elliptic curve points
     */
    private final EllipticCurveOperator operator;
    
    
    public SMPMBehavior(SMPMContainer container, EllipticCurveOperator operator, int windowSize) {
        this.container = container;
        this.operator = operator;
    }
    
    @Override
    public EllipticCurvePoint mpm(BigInteger k, BigInteger l, EllipticCurvePoint P, EllipticCurvePoint Q) {
        Tuple<EllipticCurvePoint,EllipticCurvePoint> decPoints = container.getPoints();
        if(!decPoints.getK().equals(P)||!decPoints.getV().equals(Q))
            throw new RuntimeException("container does not match required points");
        
        EllipticCurvePoint R;
        R = container.get(k, l);
        if(R!=null) return R;
        
        int omega = container.getOmega();
        int t = getBiggestLength(k, l);
        int d = t/omega;
        if(d % omega !=0)
            d++;
        
        List<BigInteger> K = splitToBlocks(k, omega, d);
        List<BigInteger> L = splitToBlocks(l, omega, d);
        R = EllipticCurvePoint.POINT_ON_INFINITY;
        
        for(int i=d-1; i>=0; i--){
            R = operator.mul(BigInteger.valueOf(2).pow(omega), R);
            EllipticCurvePoint precal = container.get(K.get(i), L.get(i));
            if(precal ==null) throw new RuntimeException("precalculated value does not exist in the container");
            R = operator.add(R, precal);
        }
        return R;
    }   
    
    private int getBiggestLength(BigInteger k, BigInteger l){
        return k.compareTo(l) >=0? k.bitLength(): l.bitLength();
    }
    
    private List<BigInteger> splitToBlocks(BigInteger val, int blockSize, int blockCount){
        List<BigInteger> res = new LinkedList<>();
        for(int i=0;i<blockCount;i++){
            BigInteger v = BigInteger.ZERO;
            for(int j=0;j<blockSize;j++){
                if(blockSize*i+j<val.bitLength())
                    if(val.testBit(blockSize*i+j))
                        v = v.add(BigInteger.ONE.shiftLeft(j)); // v+= 2^j
            }
            res.add(v);
        }
        return res;
    }
}
