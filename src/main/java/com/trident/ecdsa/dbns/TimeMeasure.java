/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.trident.ecdsa.dbns;

import com.trident.crypto.algo.ECDSA;
import com.trident.crypto.algo.ECDSAKey;
import com.trident.crypto.elliptic.EllipticCurveOperator;
import com.trident.crypto.elliptic.EllipticCurvePoint;
import com.trident.crypto.elliptic.arithmetics.EllipticCurveArithmetics;
import com.trident.crypto.elliptic.nist.SECP;
import com.trident.crypto.util.Tuple;
import com.trident.ecdsa.dbns.smpm.SMPMBehavior;
import com.trident.ecdsa.dbns.smpm.SMPMContainer;
import com.trident.ecdsa.dbns.smpm.SMPMContainerImpl;
import com.trident.ecdsa.dbns.smpm.SMPMFileReader;
import com.trident.ecdsa.dbns.smpm.SMPMFileWriter;
import com.trident.ecdsa.dbns.smpm.SMPMPointCalculator;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

/**
 *
 * @author trident
 */
public class TimeMeasure {
    public static void main(String[] args) throws FileNotFoundException, IOException {
        if(args.length <3 ) throw new RuntimeException("should provide file storage path, standard ordinal, omega");
        String filename = args[0];
        File f = new File(filename);
        
        if(Integer.parseInt(args[1])>=SECP.values().length) throw new RuntimeException("wrong standard ordinal");
        SECP standard = SECP.values()[Integer.parseInt(args[1])];
        
        if(Integer.parseInt(args[2])<=0||Integer.parseInt(args[2])>32) throw new RuntimeException("wrong omega");
        int omega = Integer.parseInt(args[2]);
        
        SMPMContainer container;
        EllipticCurveOperator operator = EllipticCurveArithmetics.createFrom(standard);
        ECDSA ecdsa = new ECDSA(operator);
        ECDSAKey key = ecdsa.generateKeyPair();
        
        if(!(f.exists()&&f.isFile())){
            System.out.println("calculating and writing the points...");
            SMPMPointCalculator calculator = new SMPMPointCalculator(omega, operator, operator.getEllipticCurve().getG(), key.getKeyPub());
            Tuple<EllipticCurvePoint,EllipticCurvePoint> points = new Tuple<>(operator.getEllipticCurve().getG(), key.getKeyPub());
            container = new SMPMContainerImpl(calculator.calculateValues(), points, omega);
            SMPMFileWriter writer = new SMPMFileWriter(new FileWriter(f));
            writer.write(container);
            writer.close();
        } else {
            System.out.println("reading the points...");
            SMPMFileReader reader = new SMPMFileReader(new FileReader(f));
            container = reader.readPoints(); 
            reader.close();
        }
        
        ECDSA ecdsaSMPM = new ECDSA(EllipticCurveArithmetics.createFrom(standard), new SMPMBehavior(container, operator, omega));
        String message = "test";
        String signature = ecdsaSMPM.sign(message.getBytes(), key.getKeySec());
        if(!ecdsaSMPM.verify(message.getBytes(), key.getKeyPub(),signature))
            throw new RuntimeException("signature verification failed");
        
    }
    
}
