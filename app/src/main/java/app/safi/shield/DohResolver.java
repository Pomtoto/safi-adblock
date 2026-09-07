/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

import java.io.*;
import java.net.*;
import javax.net.ssl.HttpsURLConnection;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/** DNS-only encrypted upstream. Default platform certificate/hostname verification stays on. */
public final class DohResolver implements AutoCloseable {
    public interface Transport extends AutoCloseable { byte[] exchange(byte[] query)throws IOException; void close(); }
    public interface Events {void request();void blocked();void error();void upstreamOk();}
    public interface ConnectionFactory {HttpsURLConnection open(URL url)throws IOException;}
    public static final class HttpsTransport implements Transport {
        private static final String[] ENDPOINTS={"https://1.1.1.1/dns-query","https://1.0.0.1/dns-query","https://[2606:4700:4700::1111]/dns-query"};
        private final ConnectionFactory factory;
        private final Set<HttpsURLConnection> active=ConcurrentHashMap.newKeySet();
        private final AtomicInteger preferred=new AtomicInteger();
        private volatile boolean closed;
        public HttpsTransport(ConnectionFactory factory){this.factory=factory;}
        public HttpsTransport(){this(url -> (HttpsURLConnection)url.openConnection());}
        public byte[] exchange(byte[] query)throws IOException{
            IOException error=null;int first=preferred.get();
            for(int attempt=0;attempt<ENDPOINTS.length;attempt++){
                if(closed)throw new IOException("Resolver stopped");
                int idx=(first+attempt)%ENDPOINTS.length;HttpsURLConnection conn=null;
                try{
                    conn=factory.open(new URL(ENDPOINTS[idx]));active.add(conn);
                    if(closed)throw new IOException("Resolver stopped");
                    conn.setConnectTimeout(2500);conn.setReadTimeout(3500);conn.setRequestMethod("POST");
                    conn.setInstanceFollowRedirects(false);conn.setUseCaches(false);conn.setDoOutput(true);
                    conn.setRequestProperty("Accept","application/dns-message");
                    conn.setRequestProperty("Content-Type","application/dns-message");
                    conn.setFixedLengthStreamingMode(query.length);
                    try(OutputStream out=conn.getOutputStream()){out.write(query);}
                    if(conn.getResponseCode()!=200)throw new IOException("DNS HTTPS status: "+conn.getResponseCode());
                    String type=conn.getContentType();
                    if(type==null||!type.toLowerCase(Locale.ROOT).startsWith("application/dns-message"))throw new IOException("Invalid DNS content type");
                    ByteArrayOutputStream bytes=new ByteArrayOutputStream();
                    try(InputStream in=conn.getInputStream()){
                        byte[] buffer=new byte[2048];int n;
                        while((n=in.read(buffer))!=-1){if(bytes.size()+n>65535)throw new IOException("Oversized DNS reply");bytes.write(buffer,0,n);}
                    }
                    byte[] answer=bytes.toByteArray();DnsCodec.validateResponse(query,answer);preferred.set(idx);return answer;
                }catch(IOException e){error=e;}
                finally{if(conn!=null){active.remove(conn);conn.disconnect();}}
            }
            throw error==null?new IOException("DNS unavailable"):error;
        }
        public void close(){closed=true;for(HttpsURLConnection c:active)c.disconnect();active.clear();}
    }
    private final DomainRules rules;private final Transport transport;private final Events events;
    private final Map<String,CacheEntry> cache=new LinkedHashMap<String,CacheEntry>(64,0.75f,true){
        protected boolean removeEldestEntry(Map.Entry<String,CacheEntry> e){return size()>256;}
    };
    private static final class CacheEntry{final byte[] value;final long born,ttl;CacheEntry(byte[] v,long t){value=v.clone();born=System.nanoTime();ttl=t;}}
    public DohResolver(DomainRules rules,Transport transport,Events events){this.rules=rules;this.transport=transport;this.events=events;}
    public byte[] overloaded(byte[] query){events.request();events.error();return DnsCodec.failure(query);}
    public byte[] resolve(byte[] query){
        events.request();
        try{
            DnsCodec.Question q=DnsCodec.question(query);
            if(q.qclass!=1)return DnsCodec.unsupported(query);
            if(rules.blocks(q.host)){events.blocked();return DnsCodec.blocked(query);}
            byte[] normalized=query.clone();DnsCodec.put16(normalized,0,0);
            String key=Base64.getEncoder().encodeToString(normalized);
            CacheEntry hit;synchronized(cache){hit=cache.get(key);}
            if(hit!=null){long elapsed=(System.nanoTime()-hit.born)/1000000000;
                if(elapsed<hit.ttl)return DnsCodec.aged(hit.value,elapsed,DnsCodec.u16(query,0));
                synchronized(cache){cache.remove(key);}
            }
            byte[] reply=transport.exchange(normalized);DnsCodec.validateResponse(query,reply);events.upstreamOk();
            if(!rules.isAllowed(q.host))for(String alias:DnsCodec.aliases(reply)){
                if(rules.blocks(alias)){events.blocked();return DnsCodec.blocked(query);}
            }
            long ttl=DnsCodec.cacheTtl(reply);
            if(ttl>0&&reply.length<=8192)synchronized(cache){cache.put(key,new CacheEntry(reply,ttl));}
            return reply;
        }catch(IOException|RuntimeException e){events.error();return DnsCodec.failure(query);}
    }
    public void close(){transport.close();synchronized(cache){cache.clear();}}
}
