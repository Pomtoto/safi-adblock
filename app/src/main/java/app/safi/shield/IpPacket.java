/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

/** Only IPv4 transport to the single virtual DNS IP is routed into our TUN. */
public final class IpPacket {
    public static final int DNS_IP=0x0a6fde02; // 10.111.222.2
    public static final int TCP=6, UDP=17;
    public final int source,destination,sourcePort,destinationPort,protocol,flags,window;
    public final long seq,ack;
    public final byte[] payload;
    private static final AtomicInteger ids=new AtomicInteger();
    private IpPacket(int s,int d,int sp,int dp,int proto,long seq,long ack,int flags,int window,byte[] data){
        source=s;destination=d;sourcePort=sp;destinationPort=dp;protocol=proto;this.seq=seq;this.ack=ack;this.flags=flags;this.window=window;payload=data;
    }
    public static IpPacket parse(byte[] b,int size){
        if(size<20 || (b[0]&0xf0)!=0x40)return null;
        int ihl=(b[0]&15)*4,total=DnsCodec.u16(b,2);
        if(ihl<20||ihl>total||total>size||(DnsCodec.u16(b,6)&0x3fff)!=0)return null;
        int proto=b[9]&255;int s=(int)DnsCodec.u32(b,12),d=(int)DnsCodec.u32(b,16);
        if(proto==UDP){
            if(total<ihl+8)return null;
            int n=DnsCodec.u16(b,ihl+4);
            if(n<8||ihl+n>total)return null;
            return new IpPacket(s,d,DnsCodec.u16(b,ihl),DnsCodec.u16(b,ihl+2),proto,0,0,0,0,Arrays.copyOfRange(b,ihl+8,ihl+n));
        }
        if(proto==TCP){
            if(total<ihl+20)return null;
            int h=((b[ihl+12]>>>4)&15)*4;
            if(h<20||ihl+h>total)return null;
            return new IpPacket(s,d,DnsCodec.u16(b,ihl),DnsCodec.u16(b,ihl+2),proto,DnsCodec.u32(b,ihl+4),DnsCodec.u32(b,ihl+8),b[ihl+13]&255,DnsCodec.u16(b,ihl+14),Arrays.copyOfRange(b,ihl+h,total));
        }
        return null;
    }
    static int checksum(byte[] b,int p,int len,long seed){
        long sum=seed;
        for(int end=p+len;p+1<end;p+=2)sum+=DnsCodec.u16(b,p);
        if((len&1)!=0)sum+=(b[p]&255)<<8;
        while((sum>>>16)!=0)sum=(sum&65535)+(sum>>>16);
        return (int)(~sum)&65535;
    }
    private static byte[] header(int source,int dest,int proto,int length){
        byte[] b=new byte[length];b[0]=0x45;DnsCodec.put16(b,2,length);DnsCodec.put16(b,4,ids.incrementAndGet());
        DnsCodec.put16(b,6,0x4000);b[8]=64;b[9]=(byte)proto;DnsCodec.put32(b,12,source);DnsCodec.put32(b,16,dest);
        DnsCodec.put16(b,10,checksum(b,0,20,0));return b;
    }
    private static long pseudo(byte[] b,int proto){return (long)DnsCodec.u16(b,12)+DnsCodec.u16(b,14)+DnsCodec.u16(b,16)+DnsCodec.u16(b,18)+proto+(b.length-20);}
    public static byte[] udp(int s,int d,int sp,int dp,byte[] data){
        if(data.length>65507)throw new IllegalArgumentException("UDP too long");
        byte[] b=header(s,d,UDP,28+data.length);DnsCodec.put16(b,20,sp);DnsCodec.put16(b,22,dp);DnsCodec.put16(b,24,8+data.length);
        System.arraycopy(data,0,b,28,data.length);int check=checksum(b,20,b.length-20,pseudo(b,UDP));DnsCodec.put16(b,26,check==0?65535:check);return b;
    }
    public byte[] udpReply(byte[] data){return udp(destination,source,destinationPort,sourcePort,data);}
    public static byte[] tcp(int s,int d,int sp,int dp,long seq,long ack,int flags,int window,byte[] data){
        if(data.length>65495)throw new IllegalArgumentException("TCP too long");
        byte[] b=header(s,d,TCP,40+data.length);DnsCodec.put16(b,20,sp);DnsCodec.put16(b,22,dp);
        DnsCodec.put32(b,24,seq);DnsCodec.put32(b,28,ack);b[32]=0x50;b[33]=(byte)flags;DnsCodec.put16(b,34,window);
        System.arraycopy(data,0,b,40,data.length);DnsCodec.put16(b,36,checksum(b,20,b.length-20,pseudo(b,TCP)));return b;
    }
    public byte[] tcpReply(long seq,long ack,int flags,int window,byte[] data){return tcp(destination,source,destinationPort,sourcePort,seq,ack,flags,window,data);}
    public static boolean validChecksums(byte[] b){
        if(checksum(b,0,20,0)!=0)return false;
        int proto=b[9]&255;return checksum(b,20,b.length-20,pseudo(b,proto))==0;
    }
}
