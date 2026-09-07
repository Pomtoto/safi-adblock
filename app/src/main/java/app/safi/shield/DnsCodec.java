/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Bounds-checked DNS wire parser, shared by the app and JVM tests. */
public final class DnsCodec {
    private DnsCodec() {}
    public static int u16(byte[] b, int p) { return ((b[p] & 255) << 8) | (b[p + 1] & 255); }
    public static long u32(byte[] b, int p) { return ((long)u16(b, p) << 16) | u16(b, p + 2); }
    public static void put16(byte[] b, int p, int v) { b[p] = (byte)(v >>> 8); b[p + 1] = (byte)v; }
    public static void put32(byte[] b, int p, long v) { put16(b, p, (int)(v >>> 16)); put16(b, p + 2, (int)v); }
    private static void need(byte[] b, int p, int n) throws IOException {
        if (p < 0 || n < 0 || p > b.length - n) throw new IOException("Malformed DNS packet");
    }
    static final class Name { final String text; final int next; Name(String s, int p) { text=s; next=p; } }
    static Name name(byte[] b, int start) throws IOException {
        int p=start, next=-1, hops=0, length=0;
        StringBuilder s=new StringBuilder();
        Set<Integer> visited=new HashSet<>();
        while (true) {
            need(b,p,1);
            if (!visited.add(p) || ++hops > 128) throw new IOException("DNS compression loop");
            int n=b[p++] & 255;
            if (n==0) { if(next<0)next=p; break; }
            if ((n & 0xc0)==0xc0) {
                need(b,p,1);
                int target=((n & 63)<<8)|(b[p++] & 255);
                if(next<0)next=p;
                if(target>=b.length)throw new IOException("Invalid DNS pointer");
                p=target; continue;
            }
            if ((n & 0xc0)!=0 || n>63) throw new IOException("Invalid DNS label");
            need(b,p,n); length+=n+1;
            if(length>254)throw new IOException("DNS name too long");
            if(s.length()>0)s.append('.');
            for(int i=0;i<n;i++) {
                int c=b[p+i]&255;
                if(c<33 || c>126 || c=='.')throw new IOException("Unsupported DNS label");
                s.append((char)c);
            }
            p+=n;
        }
        return new Name(s.toString().toLowerCase(Locale.ROOT),next);
    }
    public static final class Question {
        public final String host; public final int type, qclass, end;
        Question(String h,int t,int c,int e){host=h;type=t;qclass=c;end=e;}
    }
    public static Question question(byte[] b) throws IOException {
        need(b,0,12);
        if ((u16(b,2)&0xf800)!=0 || u16(b,4)!=1)throw new IOException("Only standard one-question DNS supported");
        // Question compression is unnecessary and unsafe when returning a shortened reply.
        int scan=12;
        while(true){need(b,scan,1);int n=b[scan++]&255;if(n==0)break;if(n>63)throw new IOException("Compressed question");need(b,scan,n);scan+=n;}
        Name n=name(b,12); need(b,n.next,4);
        return new Question(n.text,u16(b,n.next),u16(b,n.next+2),n.next+4);
    }
    private static byte[] basic(byte[] query,int rcode,boolean truncated) {
        Question q=null;
        try {q=question(query);}catch(IOException ignored){}
        byte[] out=new byte[q==null?12:q.end];
        if(query.length>=2){out[0]=query[0];out[1]=query[1];}
        int flags=0x8080 | (query.length>=4 ? u16(query,2)&0x0110 : 0) | (rcode&15);
        if(truncated)flags|=0x0200;
        put16(out,2,flags);
        if(q!=null){put16(out,4,1);System.arraycopy(query,12,out,12,q.end-12);}
        return out;
    }
    public static byte[] blocked(byte[] query){return basic(query,3,false);}
    public static byte[] failure(byte[] query){return basic(query,2,false);}
    public static byte[] malformed(byte[] query){return basic(query,1,false);}
    public static byte[] unsupported(byte[] query){return basic(query,4,false);}
    public static byte[] truncated(byte[] query){return basic(query,0,true);}
    public static int udpLimit(byte[] query) {
        try {
            Question q=question(query); int p=q.end;
            int count=u16(query,6)+u16(query,8)+u16(query,10);
            if(count>128)return 512;
            for(int i=0;i<count;i++) {
                Name n=name(query,p); p=n.next; need(query,p,10);
                int type=u16(query,p),len=u16(query,p+8);
                if(type==41)return Math.max(512,Math.min(1232,u16(query,p+2)));
                p+=10; need(query,p,len);p+=len;
            }
        }catch(IOException ignored){}
        return 512;
    }
    public static void validateResponse(byte[] query,byte[] response)throws IOException {
        need(response,0,12);
        if((u16(response,2)&0x8000)==0 || (u16(response,2)&0x7800)!=0 || u16(response,4)!=1)
            throw new IOException("Invalid resolver reply");
        Question q=question(query);Name n=name(response,12);need(response,n.next,4);
        if(!q.host.equals(n.text)||q.type!=u16(response,n.next)||q.qclass!=u16(response,n.next+2))
            throw new IOException("Mismatched DNS reply");
        // Walk all records now; malformed upstream data must never reach the cache.
        records(response,null,false,0);
        response[0]=query[0]; response[1]=query[1];
    }
    private static long records(byte[] b,Set<String> aliases,boolean age,long elapsed)throws IOException {
        need(b,0,12);int p=12;
        int qs=u16(b,4);if(qs>16)throw new IOException("Too many questions");
        for(int i=0;i<qs;i++){Name n=name(b,p);p=n.next;need(b,p,4);p+=4;}
        int count=u16(b,6)+u16(b,8)+u16(b,10);
        if(count>4096)throw new IOException("Too many DNS records");
        long min=Long.MAX_VALUE;
        for(int i=0;i<count;i++) {
            Name n=name(b,p);p=n.next;need(b,p,10);
            int type=u16(b,p),len=u16(b,p+8);long ttl=u32(b,p+4);
            need(b,p+10,len);
            if(type!=41){min=Math.min(min,ttl);if(age)put32(b,p+4,Math.max(0,ttl-elapsed));}
            if(aliases!=null&&(type==5||type==39)) {
                Name alias=name(b,p+10);
                if(alias.next>p+10+len)throw new IOException("Malformed alias");
                aliases.add(alias.text);
            }
            p+=10+len;
        }
        return min==Long.MAX_VALUE?0:min;
    }
    public static Set<String> aliases(byte[] response)throws IOException {
        Set<String> out=new HashSet<>();records(response,out,false,0);return out;
    }
    public static long cacheTtl(byte[] response) {
        try {
            if((u16(response,2)&0x020f)!=0 || u16(response,6)==0)return 0;
            return Math.min(300,records(response,null,false,0));
        }catch(Exception e){return 0;}
    }
    public static byte[] aged(byte[] original,long seconds,int id)throws IOException {
        byte[] out=original.clone();records(out,null,true,seconds);put16(out,0,id);return out;
    }
    public static byte[] query(String host,int type,int id) {
        try {
            ByteArrayOutputStream out=new ByteArrayOutputStream();
            byte[] head=new byte[12];put16(head,0,id);put16(head,2,0x0100);put16(head,4,1);out.write(head);
            for(String label:host.split("\\.")){byte[] a=label.getBytes(StandardCharsets.US_ASCII);out.write(a.length);out.write(a);}
            out.write(0);out.write(type>>>8);out.write(type);out.write(0);out.write(1);return out.toByteArray();
        }catch(IOException impossible){throw new AssertionError(impossible);}
    }
}
