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
            String[] pTokens = s.split(" ");
            if(pTokens.length!=4) throw new RuntimeException("wrong line");
            declaredPoints = new Tuple<>(
                    EllipticCurvePoint.create(factory.createFrom(new BigInteger(pTokens[0])), factory.createFrom(new BigInteger(pTokens[1]))),
                    EllipticCurvePoint.create(factory.createFrom(new BigInteger(pTokens[2])), factory.createFrom(new BigInteger(pTokens[3]))));
            
            s = r.readLine();
            while (s!=null) {                
                String[] tokens = s.split(" ");
                if(tokens.length!=4) throw new RuntimeException("wrong line");
                
                BigInteger i = new BigInteger(tokens[0]);
                BigInteger j = new BigInteger(tokens[1]);
                BigInteger px = new BigInteger(tokens[2]);
                BigInteger py = new BigInteger(tokens[3]);
                
                EllipticCurvePoint p = EllipticCurvePoint.create(factory.createFrom(px), factory.createFrom(py));
                
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
