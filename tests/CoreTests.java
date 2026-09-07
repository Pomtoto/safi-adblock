/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;
import java.util.*;
import java.io.*;

public final class CoreTests {
 static int checks;
 static void check(boolean ok,String label){checks++;if(!ok)throw new AssertionError(label);}
 static Set<String> set(String...v){return new HashSet<>(Arrays.asList(v));}
 static byte[] aResponse(byte[] q){
  byte[] r=Arrays.copyOf(q,q.length+16);DnsCodec.put16(r,2,0x8180);DnsCodec.put16(r,6,1);
  int p=q.length;DnsCodec.put16(r,p,0xc00c);DnsCodec.put16(r,p+2,1);DnsCodec.put16(r,p+4,1);DnsCodec.put32(r,p+6,60);DnsCodec.put16(r,p+10,4);
  r[p+12]=93;r[p+13]=(byte)184;r[p+14]=(byte)216;r[p+15]=34;return r;
 }
 static byte[] aliasResponse(byte[] q,String target){
  byte[] full=DnsCodec.query(target,1,0),name=Arrays.copyOfRange(full,12,full.length-4);
  byte[] r=Arrays.copyOf(q,q.length+12+name.length);DnsCodec.put16(r,2,0x8180);DnsCodec.put16(r,6,1);
  int p=q.length;DnsCodec.put16(r,p,0xc00c);DnsCodec.put16(r,p+2,5);DnsCodec.put16(r,p+4,1);DnsCodec.put32(r,p+6,60);DnsCodec.put16(r,p+10,name.length);
  System.arraycopy(name,0,r,p+12,name.length);return r;
 }
 static void rules(){
  DomainRules r=new DomainRules(set("ads.example.com","tracker.net"),set("allowed.ads.example.com"),set("extra.example.org"));
  check(r.blocks("ads.example.com"),"exact");check(r.blocks("a.ads.example.com"),"subdomain");check(!r.blocks("badads.example.com"),"label boundary");check(!r.blocks("example.com"),"parent not blocked");
  check(!r.blocks("x.allowed.ads.example.com"),"allow override");check(r.blocks("EXTRA.EXAMPLE.ORG."),"case normalization");check(!r.blocks("tracker.net.evil.example"),"not substring");
  check(DomainRules.normalize(" *.EXAMPLE.com. ").equals("example.com"),"normalize");check(DomainRules.normalize("مثال.إختبار").startsWith("xn--"),"IDN");
  for(String bad:new String[]{"https://example.com","1.2.3.4","com","a..com","-a.com","a.com/path","a.com:53","x@a.com"}){
   boolean failed=false;try{DomainRules.normalize(bad);}catch(IllegalArgumentException e){failed=true;}check(failed,"reject "+bad);
  }
  check(DomainRules.parseUser("example.com\n\nEXAMPLE.COM\nfoo.org").size()==2,"user dedup");
 }
 static void dns()throws Exception{
  byte[] q=DnsCodec.query("example.com",1,4711);DnsCodec.Question question=DnsCodec.question(q);check(question.host.equals("example.com")&&question.type==1,"question decode");
  byte[] b=DnsCodec.blocked(q);check((DnsCodec.u16(b,2)&15)==3,"NXDOMAIN");check(DnsCodec.u16(b,0)==4711&&DnsCodec.u16(b,4)==1,"ID and question");check((DnsCodec.u16(b,2)&0x20)==0,"no forged AD");DnsCodec.validateResponse(q,b);
  byte[] r=aResponse(q);DnsCodec.validateResponse(q,r);check(DnsCodec.cacheTtl(r)==60,"TTL");check(DnsCodec.cacheTtl(DnsCodec.aged(r,17,99))==43,"TTL aging");check(DnsCodec.u16(DnsCodec.aged(r,17,99),0)==99,"ID rewrite");check(DnsCodec.cacheTtl(b)==0,"no negative cache");
  check(DnsCodec.aliases(aliasResponse(q,"ads.example.com")).contains("ads.example.com"),"CNAME");check(DnsCodec.udpLimit(q)==512,"UDP legacy limit");
  byte[] edns=Arrays.copyOf(q,q.length+11);DnsCodec.put16(edns,10,1);DnsCodec.put16(edns,q.length+1,41);DnsCodec.put16(edns,q.length+3,4096);check(DnsCodec.udpLimit(edns)==1232,"EDNS MTU clamp");check((DnsCodec.u16(DnsCodec.truncated(q),2)&512)!=0,"TCP fallback flag");
  byte[] compressed=new byte[18];DnsCodec.put16(compressed,4,1);compressed[12]=(byte)0xc0;compressed[13]=12;
  boolean bad=false;try{DnsCodec.question(compressed);}catch(IOException e){bad=true;}check(bad,"pointer loop rejected");
  bad=false;try{DnsCodec.validateResponse(DnsCodec.query("different.com",1,0),r);}catch(IOException e){bad=true;}check(bad,"upstream question match");
  Random rng=new Random(23);
  for(int i=0;i<4000;i++){byte[] fuzz=new byte[rng.nextInt(180)];rng.nextBytes(fuzz);try{DnsCodec.question(fuzz);}catch(IOException expected){}DnsCodec.udpLimit(fuzz);DnsCodec.failure(fuzz);IpPacket.parse(fuzz,fuzz.length);}
  check(true,"4000 malformed DNS/IP fuzz cases");
 }
 static final class Events implements DohResolver.Events{int queries,blocked,errors,ok;public void request(){queries++;}public void blocked(){blocked++;}public void error(){errors++;}public void upstreamOk(){ok++;}}
 static void resolver()throws Exception{
  DomainRules rules=new DomainRules(set("ads.example.com"),set("safe.ads.example.com"),Collections.emptySet());final int[] calls={0};Events stats=new Events();
  DohResolver.Transport t=new DohResolver.Transport(){public byte[] exchange(byte[] q){calls[0]++;return aResponse(q);}public void close(){}};
  try(DohResolver r=new DohResolver(rules,t,stats)){
   byte[] b=r.resolve(DnsCodec.query("cdn.ads.example.com",1,1));check((DnsCodec.u16(b,2)&15)==3&&calls[0]==0,"blocked stays local");r.resolve(DnsCodec.query("example.com",1,2));byte[] cached=r.resolve(DnsCodec.query("example.com",1,3));check(calls[0]==1&&DnsCodec.u16(cached,0)==3,"cache hit with ID preserved");
   r.resolve(DnsCodec.query("safe.ads.example.com",1,4));check(calls[0]==2,"allowlist");check(stats.queries==4&&stats.blocked==1&&stats.errors==0,"real counters");
  }
  Events e=new Events();DohResolver.Transport aliases=new DohResolver.Transport(){public byte[] exchange(byte[] q){return aliasResponse(q,"ads.example.com");}public void close(){}};
  try(DohResolver r=new DohResolver(rules,aliases,e)){check((DnsCodec.u16(r.resolve(DnsCodec.query("innocent.example",1,1)),2)&15)==3,"blocked CNAME");}
  DohResolver.Transport broken=new DohResolver.Transport(){public byte[] exchange(byte[] q)throws IOException{throw new IOException("offline");}public void close(){}};
  try(DohResolver r=new DohResolver(rules,broken,e)){check((DnsCodec.u16(r.resolve(DnsCodec.query("example.com",1,1)),2)&15)==2,"SERVFAIL, no plaintext fallback");}
 }
 static void packets(){
  byte[] data=DnsCodec.query("odd.example",1,34),raw=IpPacket.udp(0x0a6fde01,IpPacket.DNS_IP,45000,53,data);IpPacket p=IpPacket.parse(raw,raw.length);
  check(p!=null&&p.sourcePort==45000&&p.destinationPort==53,"UDP parser");check(Arrays.equals(data,p.payload),"UDP body");check(IpPacket.validChecksums(raw),"IP/UDP checksum");check(IpPacket.validChecksums(p.udpReply(DnsCodec.blocked(data))),"reply checksum");
  byte[] tcp=IpPacket.tcp(0x0a6fde01,IpPacket.DNS_IP,45000,53,0xfffffff0L,0,2,4096,new byte[0]);check(IpPacket.validChecksums(tcp),"TCP checksum");check(IpPacket.parse(tcp,tcp.length).seq==0xfffffff0L,"unsigned seq");raw[6]=0x20;check(IpPacket.parse(raw,raw.length)==null,"IP fragments excluded");
 }
 static void tcp()throws Exception{
  final Deque<IpPacket> output=new ArrayDeque<>();final int[] resolved={0};
  TcpDnsProxy server=new TcpDnsProxy(raw->{check(IpPacket.validChecksums(raw),"emitted TCP checksum");output.add(IpPacket.parse(raw,raw.length));},(q,answer)->{resolved[0]++;answer.accept(aResponse(q));});
  int ip=0x0a6fde01,port=42500;long seq=0xfffffff0L;send(server,ip,port,seq,0,2,24,new byte[0]);IpPacket hello=output.remove();check(hello.flags==18&&hello.ack==((seq+1)&0xffffffffL),"SYN ACK");long ack=(hello.seq+1)&0xffffffffL;seq=(seq+1)&0xffffffffL;send(server,ip,port,seq,ack,16,24,new byte[0]);
  byte[] query=DnsCodec.query("example.com",1,555),frame=new byte[query.length+2];DnsCodec.put16(frame,0,query.length);System.arraycopy(query,0,frame,2,query.length);
  send(server,ip,port,seq,ack,24,24,Arrays.copyOfRange(frame,0,1));seq=(seq+1)&0xffffffffL;check(resolved[0]==0,"split prefix buffering");long before=seq;byte[] second=Arrays.copyOfRange(frame,1,frame.length);send(server,ip,port,seq,ack,24,24,second);seq=(seq+second.length)&0xffffffffL;
  ByteArrayOutputStream result=new ByteArrayOutputStream();int guard=0;
  while(!output.isEmpty()&&guard++<100){IpPacket p=output.remove();if(p.payload.length>0){check(p.seq==ack,"flow-controlled ordering");result.write(p.payload);ack=(ack+p.payload.length)&0xffffffffL;send(server,ip,port,seq,ack,16,24,new byte[0]);}}
  byte[] response=result.toByteArray();check(response.length>2&&DnsCodec.u16(response,0)==response.length-2,"DNS TCP framing");check(DnsCodec.u16(response,2)==555&&resolved[0]==1,"single request with ID");
  send(server,ip,port,before,ack,24,24,second);check(resolved[0]==1,"duplicate not repeated");output.clear();send(server,ip,port,seq,ack,17,24,new byte[0]);seq=(seq+1)&0xffffffffL;
  while(!output.isEmpty()){IpPacket p=output.remove();if((p.flags&1)!=0){ack=(p.seq+1)&0xffffffffL;send(server,ip,port,seq,ack,16,24,new byte[0]);}}
  check(server.size()==0,"FIN close");server.close();
 }
 static void send(TcpDnsProxy s,int ip,int port,long seq,long ack,int flags,int window,byte[] data){byte[] raw=IpPacket.tcp(ip,IpPacket.DNS_IP,port,53,seq,ack,flags,window,data);s.accept(IpPacket.parse(raw,raw.length));}
 public static void main(String[] args)throws Exception{
  rules();dns();resolver();packets();tcp();
  if(args.length>0){Set<String> domains=DomainRules.readList(new FileInputStream(args[0]));DomainRules list=new DomainRules(domains,Collections.emptySet(),Collections.emptySet());check(list.count()>30000,"real list");check(list.blocks("pagead2.googlesyndication.com"),"ad domain blocked");check(!list.blocks("example.com"),"normal domain allowed");System.out.println("Bundled list: "+list.count()+" domains");}
  if(Arrays.asList(args).contains("--live")){try(DohResolver.HttpsTransport t=new DohResolver.HttpsTransport()){byte[] q=DnsCodec.query("example.com",1,1234),a=t.exchange(q);DnsCodec.validateResponse(q,a);check((DnsCodec.u16(a,2)&15)==0&&DnsCodec.u16(a,6)>0,"live HTTPS DNS");System.out.println("Live Cloudflare DoH: PASS (default TLS verification, wire-format POST)");}}
  System.out.println("PASS: "+checks+" assertions + 4000 malformed-packet fuzz cases");
 }
}
