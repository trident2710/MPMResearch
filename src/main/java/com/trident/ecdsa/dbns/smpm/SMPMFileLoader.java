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
import java.io.File;
import java.io.FileReader;
import java.math.BigInteger;
import java.util.Map;
import java.util.TreeMap;

/**
 * loads the pre-calculated elliptic curve points 
 * from file storage
 * @author trident
 */
public class SMPMFileLoader implements SMPMContainer{
    
    private Map<BigInteger,Map<BigInteger,EllipticCurvePoint>> values;
    private final File container;
    private int omega = -1;
    private Tuple<EllipticCurvePoint,EllipticCurvePoint> declaredPoints;
    
    public SMPMFileLoader(String filePath){
        this.container = new File(filePath);
        if(!container.isFile()) 
            throw new RuntimeException("unable to read");
    }
    
    @Override
    public EllipticCurvePoint get(BigInteger i, BigInteger j) {
        if(values==null)
            loadValues();
        return values.get(i).get(j);     
    }
    
    @Override
    public int getOmega() {
        if(omega<0)
            loadValues();
        return omega;
    }

    @Override
    public Tuple<EllipticCurvePoint, EllipticCurvePoint> getPoints() {
        if(declaredPoints ==null)
            loadValues();
        return declaredPoints;
    }
    
    private void loadValues(){
        FiniteFieldElementFactory factory = new FiniteFieldElementFactory();
        try(BufferedReader r = new BufferedReader(new FileReader(container))) {
            
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
            
            values = new TreeMap<>();
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
        } catch (Exception ex) {
            throw new RuntimeException("unable to read");
        } 
    }  
}
