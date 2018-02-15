/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.trident.ecdsa.dbns.smpm;

import com.trident.crypto.elliptic.EllipticCurvePoint;
import com.trident.crypto.util.Tuple;
import java.math.BigInteger;

/**
 * container of pre-calculated points for SMPM
 * (simultaneous multiple point multiplication) algorithm
 * @author trident
 */
public interface SMPMContainer {
    /**
     * lookup for pre-calculated iP+ jQ point where P and Q are the elliptic curve points for which this pre-calculation was done
     * @param i
     * @param j
     * @return Z = iP + jQ
     */
    EllipticCurvePoint get(BigInteger i, BigInteger j);
    
    /**
     * following to algorithm it is needed to calculate iP + jQ for all i,j : [0, 2^omega - 1]
     * @return omega
     */
    int getOmega();
    
    /**
     * get the points P and Q for which the values are pre-calculated
     * @return 
     */
    Tuple<EllipticCurvePoint, EllipticCurvePoint> getPoints();
}
