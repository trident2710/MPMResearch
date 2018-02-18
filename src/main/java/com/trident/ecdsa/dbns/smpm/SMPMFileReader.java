/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.trident.ecdsa.dbns.smpm;

import com.trident.crypto.elliptic.EllipticCurvePoint;
import com.trident.crypto.field.element.FiniteFieldElementFactory;
import com.trident.crypto.util.Tuple;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;
import java.util.Map;
import java.util.TreeMap;

/**
 * loads the pre-calculated elliptic curve points 
 * from file storage
 * @author trident
 */
public class SMPMFileReader extends Reader{
    
    private final Reader reader;
    
    public SMPMFileReader(Reader reader){
        this.reader = reader;
    }
        
    public SMPMContainer readPoints() throws IOException{
        
        Map<BigInteger,Map<BigInteger,EllipticCurvePoint>> values = new TreeMap<>();
        int omega = -1;
        Tuple<EllipticCurvePoint,EllipticCurvePoint> declaredPoints;
        
        FiniteFieldElementFactory factory = new FiniteFieldElementFactory();
        try(BufferedReader r = new BufferedReader(reader)) {
            
            String s = r.readLine();
            if(s ==null) throw new RuntimeException("unable to read");
            omega = Integer.parseInt(s);
            
            s = r.readLine();
            if(s ==null) throw new RuntimeException("unable to read");
            String[] pTokens = s.split(":");
            if(pTokens.length!=2) throw new RuntimeException("wrong line");
            String[] PT = pTokens[0].split(";");
            if(PT.length!=2) throw new RuntimeException("wrong line");
            String[] QT = pTokens[1].split(";");
            if(QT.length!=2) throw new RuntimeException("wrong line");
                
            declaredPoints = new Tuple<>(
                    EllipticCurvePoint.create(factory.createFrom(new BigInteger(PT[0],16)), factory.createFrom(new BigInteger(PT[1],16))),
                    EllipticCurvePoint.create(factory.createFrom(new BigInteger(QT[0],16)), factory.createFrom(new BigInteger(QT[1],16))));
            
            s = r.readLine();
            while (s!=null) {                
                String[] tokens = s.split(":");
                if(tokens.length!=2) throw new RuntimeException("wrong line");
                String[] ijt = tokens[0].split(";");
                if(ijt.length!=2) throw new RuntimeException("wrong line");
                
                BigInteger i = new BigInteger(ijt[0]);
                BigInteger j = new BigInteger(ijt[1]);
                
                EllipticCurvePoint p = null;
                if(tokens[1].equals(EllipticCurvePoint.POINT_ON_INFINITY.toString())){
                    p = EllipticCurvePoint.POINT_ON_INFINITY;
                } else{
                    String[] pt = tokens[1].split(";");
                    if(pt.length!=2) throw new RuntimeException("wrong line");
                    BigInteger px = new BigInteger(pt[0],16);
                    BigInteger py = new BigInteger(pt[1],16);
                    p = EllipticCurvePoint.create(factory.createFrom(px), factory.createFrom(py));
                }

                if(!values.containsKey(i)){
                    values.put(i, new TreeMap<>());
                }
                values.get(i).put(j, p);
                s = r.readLine();
            }
            r.close();   
        } 
        return new SMPMContainerImpl(values, declaredPoints, omega);
    }  

    @Override
    public int read(char[] cbuf, int off, int len) throws IOException {
        return reader.read(cbuf, off, len);
    }

    @Override
    public void close() throws IOException {
        reader.close();
    }
}
