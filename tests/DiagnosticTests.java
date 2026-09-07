/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

public final class DiagnosticTests {
    static int tests;
    static void check(boolean ok,String message){tests++;if(!ok)throw new AssertionError(message);}
    static void recorder()throws Exception{
        AtomicLong clock=new AtomicLong(1000);DiagnosticRecorder r=new DiagnosticRecorder(clock::get);
        check(r.ticket()==0&&!r.snapshot().exists,"off by default");r.record(1,"example.com",DiagnosticRecorder.ALLOWED);
        check(r.snapshot().rows.isEmpty(),"off means no record");
        r.start("LIGHT");long first=r.ticket();check(first!=0&&r.snapshot().remainingSeconds==120,"explicit opt-in 120s");
        r.record(0,"outside.example",1);r.record(first,"EXAMPLE.COM",1);clock.addAndGet(2000);r.record(first,"example.com",1);
        DiagnosticRecorder.Snapshot s=r.snapshot();check(s.rows.size()==1&&s.rows.get(0).count==2,"dedup and normalize");check(s.rows.get(0).lastMs==2000,"relative time only");
        r.record(first,"example.com",2);check(r.snapshot().rows.size()==2,"separate allow/block decisions");
        r.record(first,"https://example.com/?private=secret",1);r.record(first,"evil\nheader",1);r.record(first,"",1);r.record(first,"example.com",99);
        check(r.snapshot().observed==3,"no URL, control characters, or invalid status");
        r.stop();r.record(first,"late.example",1);check(!r.isRecording()&&r.snapshot().observed==3,"stop keeps rows but rejects late completion");
        r.start("NORMAL");long second=r.ticket();check(second!=first&&r.snapshot().rows.isEmpty(),"new session clears old rows and ticket");
        r.record(first,"old-query.example",1);check(r.snapshot().rows.isEmpty(),"in-flight previous session ignored");
        for(int i=0;i<300;i++)r.record(second,"d"+i+".example",1);
        check(r.snapshot().rows.size()==128&&r.snapshot().observed==300,"strict memory cap");
        String report=r.report();check(report.contains("NOT a per-app attribution")&&report.contains("NOT proof")&&!report.contains("https://"),"report declares scope and avoids URLs");
        long before=r.snapshot().observed;clock.addAndGet(DiagnosticRecorder.CAPTURE_MS);r.record(second,"after-window.example",1);
        check(r.ticket()==0&&!r.snapshot().recording&&r.snapshot().observed==before,"automatic two-minute stop");
        clock.addAndGet(DiagnosticRecorder.RETAIN_MS);r.expire();check(!r.snapshot().exists&&r.snapshot().rows.isEmpty(),"retention expiry clears all data");
        r.start("LIGHT");r.record(r.ticket(),"delete.example",1);r.clear();check(r.snapshot().rows.isEmpty()&&r.ticket()==0,"explicit clear disables capture");
        // Snapshot is immutable and independent of later writes.
        r.start("LIGHT");long t=r.ticket();r.record(t,"one.example",1);DiagnosticRecorder.Snapshot frozen=r.snapshot();r.record(t,"two.example",1);
        check(frozen.rows.size()==1&&r.snapshot().rows.size()==2,"immutable snapshot");
        boolean denied=false;try{frozen.rows.clear();}catch(UnsupportedOperationException e){denied=true;}check(denied,"external mutation rejected");
        // Bound and synchronize concurrent request completions.
        r.clear();r.start("NORMAL");long concurrent=r.ticket();ExecutorService pool=Executors.newFixedThreadPool(8);
        for(int worker=0;worker<8;worker++)pool.submit(()->{for(int i=0;i<200;i++)r.record(concurrent,"host"+i+".example",1);});
        pool.shutdown();check(pool.awaitTermination(10,TimeUnit.SECONDS),"workers complete");check(r.snapshot().observed==1600&&r.snapshot().rows.size()<=128,"thread-safe counting and bound");
    }
    static void resolverHooks()throws Exception{
        AtomicLong clock=new AtomicLong(50);DiagnosticRecorder rec=new DiagnosticRecorder(clock::get);
        DomainRules rules=new DomainRules(new HashSet<>(Arrays.asList("ads.example.com")),Collections.emptySet(),Collections.emptySet());
        DohResolver.Events events=new DohResolver.Events(){
            public void request(){}public void blocked(){}public void error(){}public void upstreamOk(){}
            public long diagnosticTicket(){return rec.ticket();}
            public void diagnostic(long ticket,String host,int status){rec.record(ticket,host,status);}
        };
        DohResolver.Transport transport=new DohResolver.Transport(){public byte[] exchange(byte[] q){return CoreTests.aResponse(q);}public void close(){}};
        try(DohResolver resolver=new DohResolver(rules,transport,events)){
            resolver.resolve(DnsCodec.query("ads.example.com",1,1));check(rec.snapshot().rows.isEmpty(),"real resolver logging off by default");
            rec.start("LIGHT");resolver.resolve(DnsCodec.query("ads.example.com",1,2));resolver.resolve(DnsCodec.query("example.com",1,3));resolver.resolve(DnsCodec.query("example.com",1,4));
            Set<Integer> states=new HashSet<>();for(DiagnosticRecorder.Row row:rec.snapshot().rows)states.add(row.status);
            check(rec.snapshot().observed==3&&states.containsAll(Arrays.asList(1,2,3)),"exactly one completion: allowed, blocked, cached");
            rec.stop();resolver.resolve(DnsCodec.query("after.example",1,5));check(rec.snapshot().observed==3,"resolver stops recording immediately");
        }
        rec.start("LIGHT");DohResolver.Transport fail=new DohResolver.Transport(){public byte[] exchange(byte[] q)throws IOException{throw new IOException("offline");}public void close(){}};
        try(DohResolver resolver=new DohResolver(rules,fail,events)){
            resolver.resolve(DnsCodec.query("example.com",1,8));check(rec.snapshot().rows.get(0).status==DiagnosticRecorder.FAILED,"network failure not labeled allowed");
            resolver.overloaded(DnsCodec.query("queue.example",1,9));check(rec.snapshot().observed==2,"overload captured only with consent");
        }
    }
    static void profiles(String lightPath,String normalPath)throws Exception{
        check(BlockProfile.from(null)==BlockProfile.LIGHT&&BlockProfile.from("../../escape")==BlockProfile.LIGHT,"safe legacy/default profile");
        check(BlockProfile.from("normal")==BlockProfile.NORMAL,"normal opt-in");
        check(BlockProfile.NORMAL.url().endsWith("/wildcard/multi-onlydomains.txt"),"canonical NORMAL upstream path");
        Set<String> normal=DomainRules.readList(new FileInputStream(normalPath));
        check(normal.size()==BlockProfile.NORMAL.baseCount,"NORMAL count matches bundled metadata");
        Set<String> light=DomainRules.readList(new FileInputStream(lightPath));
        check(light.size()==BlockProfile.LIGHT.baseCount,"LIGHT metadata retained");
        DomainRules strong=new DomainRules(normal,Collections.emptySet(),Collections.emptySet());
        check(strong.blocks("pagead2.googlesyndication.com")&&!strong.blocks("example.com"),"strong profile basic ad/normal control");
        DomainRules exception=new DomainRules(normal,new HashSet<>(Arrays.asList("pagead2.googlesyndication.com")),Collections.emptySet());
        check(!exception.blocks("pagead2.googlesyndication.com"),"user allowlist still has priority in NORMAL");
        System.out.println("Profile tests: LIGHT "+light.size()+", NORMAL "+normal.size()+" bundled domains");
    }
    public static void main(String[] args)throws Exception{recorder();resolverHooks();profiles(args[0],args[1]);System.out.println("PASS: "+tests+" diagnostics/privacy/profile assertions");}
}
