/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.trident.ecdsa.dbns;

import com.trident.crypto.algo.ECDSA;
import com.trident.crypto.algo.ECDSAKey;
import com.trident.crypto.algo.io.ECDSAKeyReader;
import com.trident.crypto.algo.io.ECDSAKeyWriter;
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
        
        args = new String[3];
        args[0] = "pointstore.smpm";
        args[1] = "ecdsa_keystore";
        args[2] = ""+4;
        
        if(args.length <3 ) throw new RuntimeException("should provide file storage path, keystore, standard ordinal, omega");
        String filename = args[0];
        File pointstore = new File(filename);
        File keystore = new File(args[1]);
        
        
        if(Integer.parseInt(args[2])<=0||Integer.parseInt(args[2])>32) throw new RuntimeException("wrong omega");
        int omega = Integer.parseInt(args[2]);
        
        SMPMContainer container;
        EllipticCurveOperator operator = EllipticCurveArithmetics.createFrom(SECP.SECP112R1);
        ECDSAKey key;
                
        if(!(pointstore.exists()&&pointstore.isFile())){
            System.out.println("calculating and writing the key");
            ECDSAKeyWriter kWriter = new ECDSAKeyWriter(new FileWriter(keystore));
            ECDSA ecdsa = new ECDSA(operator);
            key = ecdsa.generateKeyPair();
            kWriter.write(key);
            kWriter.close();
            
            System.out.println("calculating and writing the points...");
            SMPMPointCalculator calculator = new SMPMPointCalculator(omega, operator, operator.getEllipticCurve().getG(), key.getKeyPub());
            Tuple<EllipticCurvePoint,EllipticCurvePoint> points = new Tuple<>(operator.getEllipticCurve().getG(), key.getKeyPub());
            container = new SMPMContainerImpl(calculator.calculateValues(), points, omega);
            SMPMFileWriter writer = new SMPMFileWriter(new FileWriter(pointstore));
            writer.write(container);
            writer.close();
        } else {
            System.out.println("reading the keystore...");
            ECDSAKeyReader kReader =new ECDSAKeyReader(new FileReader(keystore));
            key = kReader.readECDSAKey();
            
            System.out.println("reading the points...");
            SMPMFileReader reader = new SMPMFileReader(new FileReader(pointstore));
            container = reader.readPoints(); 
            reader.close();
        }
        
        ECDSA ecdsaSMPM = new ECDSA(operator, new SMPMBehavior(container, operator, omega));
        String message = "test";
        String signature = ecdsaSMPM.sign(message.getBytes(), key.getKeySec());
        
        if(!ecdsaSMPM.verify(message.getBytes(), key.getKeyPub(),signature))
            throw new RuntimeException("signature verification failed");    
    }
    
}
