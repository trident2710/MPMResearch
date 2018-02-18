/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.trident.ecdsa.dbns.smpm;

import com.trident.crypto.elliptic.EllipticCurvePoint;
import com.trident.crypto.util.Tuple;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.Writer;

/**
 *
 * @author trident
 */
public class SMPMFileWriter extends Writer{

    private final Writer writer;
    
    public SMPMFileWriter(Writer writer){
        this.writer = writer;
    }
    
    public void write(SMPMContainer container) throws IOException{
        try (BufferedWriter w = new BufferedWriter(writer)){
            String omegaString = ""+container.getOmega();
            w.write(omegaString);
            w.newLine();
            StringBuilder pointsString = new StringBuilder();
            Tuple<EllipticCurvePoint,EllipticCurvePoint> points = container.getPoints();
            pointsString
                    .append(points.getK().toString(16)).append(":")
                    .append(points.getV().toString(16));
            
            w.write(pointsString.toString());
            w.newLine();
            
            container.getAll().forEach((i,set)->{
                set.forEach((j,point)->{
                    StringBuilder line = new StringBuilder();
                    line
                            .append(i.toString(10)).append(";").append(j.toString(10)).append(":")
                            .append(point.toString(16));
                    
                    try {
                        w.write(line.toString());
                        w.newLine();
                    } catch (IOException ex) { 
                        throw new RuntimeException("unable to write");
                    }
                });
            });   
        } 
    }
    
    @Override
    public void write(char[] cbuf, int off, int len) throws IOException {
        writer.write(cbuf, off, len);
    }

    @Override
    public void flush() throws IOException {
        writer.flush();
    }

    @Override
    public void close() throws IOException {
        writer.close();
    }  
}
