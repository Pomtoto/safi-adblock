/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

import java.util.*;
import java.util.function.LongSupplier;

/** Explicit opt-in, bounded in-memory DNS diagnostics. No file/network/Android API. */
public final class DiagnosticRecorder {
    public static final int ALLOWED=1, BLOCKED=2, CACHED=3, FAILED=4;
    public static final long CAPTURE_MS=120000, RETAIN_MS=900000;
    public static final int MAX_ROWS=128;
    private final LongSupplier clock;
    private final LinkedHashMap<String,Row> rows=new LinkedHashMap<>(128,0.75f,true);
    private long epoch,startedAt,captureUntil,retainUntil,observed;
    private String profile="";

    public DiagnosticRecorder(LongSupplier clock){this.clock=clock;}
    public static final class Row {
        public final String domain; public final int status; public final long firstMs,lastMs,count;
        Row(String d,int s,long first,long last,long count){domain=d;status=s;firstMs=first;lastMs=last;this.count=count;}
    }
    public static final class Snapshot {
        public final boolean recording,exists; public final long remainingSeconds,observed;
        public final String profile; public final List<Row> rows;
        Snapshot(boolean recording,boolean exists,long remaining,long observed,String profile,List<Row> rows){
            this.recording=recording;this.exists=exists;remainingSeconds=remaining;this.observed=observed;this.profile=profile;
            this.rows=Collections.unmodifiableList(rows);
        }
    }
    private void clearInternal(){
        rows.clear();startedAt=0;captureUntil=0;retainUntil=0;observed=0;profile="";
        epoch++;if(epoch<=0)epoch=1;
    }
    private void expire(long now){if(retainUntil!=0&&now>=retainUntil)clearInternal();}
    private boolean active(long now){return retainUntil!=0&&captureUntil!=0&&now<captureUntil;}
    public synchronized void start(String profile){
        clearInternal();long now=clock.getAsLong();startedAt=now;captureUntil=now+CAPTURE_MS;retainUntil=now+RETAIN_MS;
        this.profile=profile==null?"":profile;
    }
    /** Called at request entry, before even parsing a DNS name. */
    public synchronized long ticket(){long now=clock.getAsLong();expire(now);return active(now)?epoch:0;}
    public synchronized boolean isRecording(){return ticket()!=0;}
    public synchronized void stop(){expire(clock.getAsLong());captureUntil=0;}
    public synchronized void clear(){clearInternal();}
    public synchronized void expire(){expire(clock.getAsLong());}
    public synchronized void record(long ticket,String domain,int status){
        long now=clock.getAsLong();expire(now);
        if(ticket==0||ticket!=epoch||!active(now)||domain==null||domain.isEmpty()||domain.length()>253)return;
        if(status<ALLOWED||status>FAILED)return;
        // Keep ordinary DNS names only; never URLs, payloads, control characters, or query strings.
        for(int i=0;i<domain.length();i++){
            char c=domain.charAt(i);
            if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='.'||c=='-'||c=='_'))return;
        }
        domain=domain.toLowerCase(Locale.ROOT);observed++;
        String key=domain+"\t"+status;Row previous=rows.get(key);long relative=Math.max(0,now-startedAt);
        rows.put(key,new Row(domain,status,previous==null?relative:previous.firstMs,relative,previous==null?1:previous.count+1));
        if(rows.size()>MAX_ROWS){Iterator<String> i=rows.keySet().iterator();i.next();i.remove();}
    }
    public synchronized Snapshot snapshot(){
        long now=clock.getAsLong();expire(now);boolean recording=active(now);
        return new Snapshot(recording,retainUntil!=0,recording?Math.max(0,(captureUntil-now+999)/1000):0,observed,profile,new ArrayList<>(rows.values()));
    }
    public static String statusName(int status){
        switch(status){case ALLOWED:return "ALLOWED";case BLOCKED:return "BLOCKED";case CACHED:return "CACHED_ALLOWED";default:return "DNS_FAILED";}
    }
    /** Plain text only. Returned to the local UI; export requires a separate user action. */
    public String report(){
        Snapshot s=snapshot();
        StringBuilder out=new StringBuilder("Safi — temporary DNS diagnostic\n");
        out.append("Scope: all DNS passing through Safi, NOT a per-app attribution.\n")
           .append("No URLs, content, device IDs, or request payloads are included.\n")
           .append("An allowed domain is NOT proof that it serves an ad.\n")
           .append("Private DNS, app-owned DoH, direct IP, and cached video can bypass this view.\n")
           .append("Profile at start: ").append(s.profile).append('\n')
           .append("Capture: ").append(s.recording?"recording":"stopped").append('\n')
           .append("Observed completions: ").append(s.observed).append('\n')
           .append("Rows retained: ").append(s.rows.size()).append('/').append(MAX_ROWS).append("\n\n")
           .append("Last second | Result | Count | Domain\n");
        for(Row row:s.rows)out.append(row.lastMs/1000).append(" | ").append(statusName(row.status)).append(" | ").append(row.count).append(" | ").append(row.domain).append('\n');
        return out.toString();
    }
}
