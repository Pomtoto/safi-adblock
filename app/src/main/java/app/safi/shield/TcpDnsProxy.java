/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

import java.util.*;
import java.security.SecureRandom;

/** Bounded TCP endpoint, only for DNS on the virtual IPv4 address.
 * Handles sequence wrap, retransmissions, pipelining, flow control and FIN/RST.
 * It is NOT a general TCP tunnel and never intercepts web traffic. */
public final class TcpDnsProxy {
    public interface Sink { void write(byte[] packet); }
    public interface Answer { void accept(byte[] answer); }
    public interface Handler { void resolve(byte[] query, Answer answer); }
    private static final byte[] EMPTY=new byte[0];
    private static final int FIN=1,SYN=2,RST=4,PSH=8,ACK=16;
    private final Map<Long,Conn> connections=new HashMap<>();
    private final Sink sink; private final Handler handler;
    private final SecureRandom random=new SecureRandom();
    private static long add(long a,long b){return (a+b)&0xffffffffL;}
    private static long now(){return System.nanoTime()/1000000;}
    private static long key(IpPacket p){return ((long)p.source<<16)^(long)p.sourcePort;}
    private static final class Segment {
        long seq;int flags;byte[] data;long sent;int tries;
        Segment(long s,int f,byte[] d){seq=s;flags=f;data=d;sent=now();}
        long end(){return add(seq,data.length+((flags&SYN)!=0?1:0)+((flags&FIN)!=0?1:0));}
    }
    private static final class Frame { final byte[] data;int pos;Frame(byte[] b){data=b;} }
    private static final class Conn {
        final IpPacket first;final long key,isn,clientIsn;
        long clientNext,serverNext,lastAck,lastActivity=now();
        boolean established,peerClosed,finSent;int jobs,window,queued;
        byte[] input=EMPTY;
        final Deque<Segment> unacked=new ArrayDeque<>();
        final Deque<Frame> output=new ArrayDeque<>();
        Conn(IpPacket p,long s){first=p;key=key(p);isn=s;clientIsn=p.seq;clientNext=add(p.seq,1);serverNext=s;lastAck=s;window=p.window;}
    }
    public TcpDnsProxy(Sink sink,Handler handler){this.sink=sink;this.handler=handler;}
    public synchronized int size(){return connections.size();}
    public synchronized void close(){connections.clear();}
    private int advertised(Conn c){return Math.max(0,Math.min(65535,131074-c.input.length));}
    private void raw(Conn c,long seq,int flags,byte[] data){sink.write(c.first.tcpReply(seq,c.clientNext,flags,advertised(c),data));}
    private void send(Conn c,int flags,byte[] data){
        Segment s=new Segment(c.serverNext,flags,data);raw(c,s.seq,flags,data);
        if(data.length>0||(flags&(SYN|FIN))!=0){c.unacked.add(s);c.serverNext=s.end();}
    }
    private void ack(Conn c){raw(c,c.serverNext,ACK,EMPTY);}
    private void reset(Conn c){raw(c,c.serverNext,RST|ACK,EMPTY);connections.remove(c.key);}
    private void unknown(IpPacket p){
        if((p.flags&RST)!=0)return;
        if((p.flags&ACK)!=0)sink.write(p.tcpReply(p.ack,0,RST,0,EMPTY));
        else sink.write(p.tcpReply(0,add(p.seq,p.payload.length+((p.flags&SYN)!=0?1:0)+((p.flags&FIN)!=0?1:0)),RST|ACK,0,EMPTY));
    }
    public synchronized void accept(IpPacket p){
        if(p.protocol!=IpPacket.TCP||p.destination!=IpPacket.DNS_IP||p.destinationPort!=53)return;
        long key=key(p);Conn c=connections.get(key);
        if((p.flags&RST)!=0){connections.remove(key);return;}
        if((p.flags&SYN)!=0){
            if((p.flags&ACK)!=0){unknown(p);return;}
            if(c!=null&&c.clientIsn==p.seq){raw(c,c.isn,SYN|ACK,EMPTY);return;}
            if(c==null&&connections.size()>=64){unknown(p);return;}
            c=new Conn(p,random.nextInt()&0xffffffffL);connections.put(key,c);send(c,SYN|ACK,EMPTY);return;
        }
        if(c==null){unknown(p);return;}
        c.lastActivity=now();
        if((p.flags&ACK)==0){ack(c);return;}
        int advance=(int)(p.ack-c.lastAck),flight=(int)(c.serverNext-c.lastAck);
        if(advance<0 || advance>flight){ack(c);return;}
        c.lastAck=p.ack;c.window=p.window;
        while(!c.unacked.isEmpty()){
            Segment s=c.unacked.peek();
            if((int)(p.ack-s.end())>=0){c.unacked.remove();continue;}
            int n=(int)(p.ack-s.seq);
            if(n>0&&n<s.data.length&&(s.flags&(SYN|FIN))==0){s.data=Arrays.copyOfRange(s.data,n,s.data.length);s.seq=p.ack;}
            break;
        }
        if(!c.established){if(p.ack!=add(c.isn,1))return;c.established=true;}
        if(c.finSent&&c.unacked.isEmpty()){connections.remove(key);return;}
        int duplicate=(int)(c.clientNext-p.seq);
        if(duplicate<0 || duplicate>p.payload.length){ack(c);pump(c);return;}
        int fresh=p.payload.length-duplicate;
        if(fresh>0){
            if(c.peerClosed||c.input.length+fresh>131074){reset(c);return;}
            byte[] next=Arrays.copyOf(c.input,c.input.length+fresh);
            System.arraycopy(p.payload,duplicate,next,c.input.length,fresh);c.input=next;
            c.clientNext=add(c.clientNext,fresh);
        }
        if((p.flags&FIN)!=0&&!c.peerClosed){c.clientNext=add(c.clientNext,1);c.peerClosed=true;}
        if(fresh>0||(p.flags&FIN)!=0)ack(c);
        process(c);pump(c);
    }
    private void process(Conn c){
        while(connections.get(c.key)==c&&c.jobs<8&&c.input.length>=2){
            int size=DnsCodec.u16(c.input,0);
            if(size<12){reset(c);return;}
            if(c.input.length<size+2)break;
            byte[] query=Arrays.copyOfRange(c.input,2,size+2);
            c.input=Arrays.copyOfRange(c.input,size+2,c.input.length);c.jobs++;
            handler.resolve(query, answer -> answered(c,answer));
        }
        if(c.peerClosed&&c.jobs==0&&c.input.length!=0)reset(c);
    }
    private synchronized void answered(Conn c,byte[] data){
        if(connections.get(c.key)!=c)return;
        c.jobs--;
        if(data.length>65535||c.queued+data.length+2>262144){reset(c);return;}
        byte[] frame=new byte[data.length+2];DnsCodec.put16(frame,0,data.length);System.arraycopy(data,0,frame,2,data.length);
        c.output.add(new Frame(frame));c.queued+=frame.length;
        process(c);pump(c);
    }
    private void pump(Conn c){
        if(connections.get(c.key)!=c||!c.established||c.finSent)return;
        while(!c.output.isEmpty()){
            int room=c.window-(int)(c.serverNext-c.lastAck);if(room<=0)break;
            Frame f=c.output.peek();int n=Math.min(512,Math.min(room,f.data.length-f.pos));
            byte[] bytes=Arrays.copyOfRange(f.data,f.pos,f.pos+n);f.pos+=n;c.queued-=n;
            send(c,ACK|PSH,bytes);if(f.pos==f.data.length)c.output.remove();
        }
        if(c.peerClosed&&c.jobs==0&&c.input.length==0&&c.output.isEmpty()&&c.window>(int)(c.serverNext-c.lastAck)){
            send(c,FIN|ACK,EMPTY);c.finSent=true;
        }
    }
    public synchronized void tick(){
        long time=now();
        for(Conn c:new ArrayList<>(connections.values())){
            if(time-c.lastActivity>60000){reset(c);continue;}
            Segment s=c.unacked.peek();if(s==null)continue;
            long delay=Math.min(8000,1000L<<Math.min(3,s.tries));
            if(time-s.sent>=delay){
                if(s.tries>=5){reset(c);continue;}
                raw(c,s.seq,s.flags,s.data);s.sent=time;s.tries++;
            }
        }
    }
}
