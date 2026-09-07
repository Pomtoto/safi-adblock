/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

import android.app.*;
import android.content.*;
import android.content.pm.ServiceInfo;
import android.net.*;
import android.os.*;
import android.system.*;
import java.io.*;
import java.net.*;
import javax.net.ssl.HttpsURLConnection;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

public final class ShieldVpnService extends VpnService {
    public static final String START="app.safi.shield.START",STOP="app.safi.shield.STOP",RESTART="app.safi.shield.RESTART";
    private static final String CHANNEL="safi_protection";
    private final Handler main=new Handler(Looper.getMainLooper());
    private final ExecutorService control=Executors.newSingleThreadExecutor();
    private final AtomicInteger generation=new AtomicInteger();
    private final Object engineLock=new Object();
    private Engine engine;
    private final Runnable pulse=new Runnable(){public void run(){
        AppState.save(ShieldVpnService.this);
        if(AppState.state==AppState.ON||AppState.state==AppState.STARTING){
            getSystemService(NotificationManager.class).notify(21,notification());main.postDelayed(this,5000);
        }
    }};
    public void onCreate(){
        super.onCreate();AppState.init(this);
        NotificationChannel channel=new NotificationChannel(CHANNEL,"حماية صافي",NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("إشعار دائم أثناء تشغيل حاجب DNS، مع زر الإيقاف");channel.setSound(null,null);channel.enableVibration(false);
        getSystemService(NotificationManager.class).createNotificationChannel(channel);
    }
    private Notification notification(){
        PendingIntent open=PendingIntent.getActivity(this,0,new Intent(this,MainActivity.class),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        PendingIntent stop=PendingIntent.getService(this,1,new Intent(this,ShieldVpnService.class).setAction(STOP),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        String detail=AppState.state==AppState.STARTING?"جارٍ تجهيز قائمة الحجب…":String.format(Locale.US,"طلبات محجوبة: %,d • VPN محلي فقط",AppState.blocked.get());
        if(AppState.lastFailure>AppState.lastSuccess)detail="تعذّر الوصول إلى DNS؛ افحص الإنترنت أو أوقف الحماية";
        return new Notification.Builder(this,CHANNEL).setSmallIcon(R.drawable.ic_shield).setContentTitle("صافي • حجب الإعلانات")
                .setContentText(detail).setContentIntent(open).setOngoing(true).setOnlyAlertOnce(true)
                .setCategory(Notification.CATEGORY_SERVICE).addAction(new Notification.Action.Builder(null,"إيقاف",stop).build()).build();
    }
    private void foreground(){
        if(Build.VERSION.SDK_INT>=34)startForeground(21,notification(),ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        else startForeground(21,notification());
    }
    public int onStartCommand(Intent intent,int flags,int startId){
        String action=intent==null?STOP:intent.getAction();
        if(STOP.equals(action)){stopRequested(startId,false);return START_NOT_STICKY;}
        if(!START.equals(action)&&!RESTART.equals(action)){stopRequested(startId,false);return START_NOT_STICKY;}
        if(START.equals(action)&&(AppState.state==AppState.ON||AppState.state==AppState.STARTING))return START_NOT_STICKY;
        boolean restart=RESTART.equals(action)&&AppState.startedAt>0;
        int token=generation.incrementAndGet();AppState.state=AppState.STARTING;AppState.message="";
        try{foreground();}catch(RuntimeException e){AppState.state=AppState.ERROR;AppState.message="لم يسمح أندرويد بتشغيل الخدمة. افتح التطبيق وحاول مجددًا.";stopSelf();return START_NOT_STICKY;}
        main.removeCallbacks(pulse);main.post(pulse);
        control.execute(() -> {
            stopEngine();
            try{
                if(token!=generation.get())return;
                if(!restart)AppState.reset();
                if(VpnService.prepare(this)!=null)throw new IOException("VPN permission required");
                DomainRules rules=AppPrefs.loadRules(this);
                if(token!=generation.get())return;
                Builder b=new Builder().setSession("صافي • DNS محلي").setMtu(1500).setBlocking(true)
                        .addAddress("10.111.222.1",32).addRoute("10.111.222.2",32).addDnsServer("10.111.222.2")
                        .allowFamily(OsConstants.AF_INET6)
                        .setConfigureIntent(PendingIntent.getActivity(this,2,new Intent(this,MainActivity.class),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE));
                if(Build.VERSION.SDK_INT>=29)b.setMetered(false);
                // Own HTTPS/bootstrap/update traffic must never recurse into this DNS proxy.
                b.addDisallowedApplication(getPackageName());
                for(String pkg:AppPrefs.excluded(this)){
                    if(pkg.equals(getPackageName()))continue;
                    try{b.addDisallowedApplication(pkg);}catch(android.content.pm.PackageManager.NameNotFoundException ignored){}
                }
                ParcelFileDescriptor tun=b.establish();
                if(tun==null)throw new IOException("VPN consent was revoked");
                Engine next;
                try{next=new Engine(tun,rules,token);}catch(Exception e){tun.close();throw e;}
                synchronized(engineLock){
                    if(token!=generation.get()){next.close();return;}
                    engine=next;next.start();
                }
                main.post(() -> {if(token==generation.get()){AppState.state=AppState.ON;AppState.message="";getSystemService(NotificationManager.class).notify(21,notification());}});
            }catch(Exception e){main.post(() -> fail(token));}
        });
        return START_NOT_STICKY;
    }
    private void fail(int token){
        if(token!=generation.get())return;
        AppState.message="تعذّر تشغيل الحماية. أوقف أي VPN آخر، وتأكد من إذن VPN ثم جرّب مجددًا.";
        AppState.state=AppState.ERROR;stopRequested(0,true);
    }
    private void stopRequested(int startId,boolean error){
        int token=generation.incrementAndGet();
        if(!error)AppState.state=AppState.STOPPING;
        main.removeCallbacks(pulse);
        control.execute(() -> {
            stopEngine();AppState.save(this);
            main.post(() -> {
                if(token!=generation.get())return;
                if(!error){AppState.state=AppState.OFF;AppState.message="";}
                stopForeground(STOP_FOREGROUND_REMOVE);if(startId>0)stopSelf(startId);else stopSelf();
            });
        });
    }
    private void stopEngine(){Engine old;synchronized(engineLock){old=engine;engine=null;}if(old!=null)old.close();}
    public void onRevoke(){AppState.message="أوقف أندرويد اتصال VPN. يمكنك تشغيله من جديد.";stopRequested(0,false);super.onRevoke();}
    public void onDestroy(){
        generation.incrementAndGet();main.removeCallbacksAndMessages(null);stopEngine();control.shutdownNow();
        AppState.save(this);if(AppState.state!=AppState.ERROR)AppState.state=AppState.OFF;
        stopForeground(STOP_FOREGROUND_REMOVE);super.onDestroy();
    }
    private Network underlying(){
        ConnectivityManager cm=getSystemService(ConnectivityManager.class);Network active=cm.getActiveNetwork(),best=null;int score=-1;
        for(Network net:cm.getAllNetworks()){
            NetworkCapabilities caps=cm.getNetworkCapabilities(net);
            if(caps==null||!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)||!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN))continue;
            int s=(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)?100:0)+(caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)?10:0)+(net.equals(active)?1000:0);
            if(s>score){score=s;best=net;}
        }
        return best;
    }
    private final class Engine implements AutoCloseable {
        private final ParcelFileDescriptor tun;private final FileInputStream input;private final FileOutputStream output;
        private final Object outputLock=new Object();private final int token;
        private final ThreadPoolExecutor workers=new ThreadPoolExecutor(8,8,30,TimeUnit.SECONDS,new ArrayBlockingQueue<>(64));
        private final DohResolver resolver;private final TcpDnsProxy tcp;
        private volatile boolean alive=true;private Thread reader;
        private final AtomicBoolean fault=new AtomicBoolean();
        Engine(ParcelFileDescriptor tun,DomainRules rules,int token){
            this.tun=tun;this.token=token;input=new FileInputStream(tun.getFileDescriptor());output=new FileOutputStream(tun.getFileDescriptor());
            DohResolver.HttpsTransport transport=new DohResolver.HttpsTransport(url -> {
                Network net=underlying();return (HttpsURLConnection)(net==null?url.openConnection():net.openConnection(url));
            });
            resolver=new DohResolver(rules,transport,new DohResolver.Events(){
                public void request(){if(alive)AppState.requests.incrementAndGet();}
                public void blocked(){if(alive)AppState.blocked.incrementAndGet();}
                public void error(){if(alive){AppState.errors.incrementAndGet();AppState.lastFailure=SystemClock.elapsedRealtime();}}
                public void upstreamOk(){if(alive)AppState.lastSuccess=SystemClock.elapsedRealtime();}
            });
            tcp=new TcpDnsProxy(this::write,this::submit);
        }
        void start(){reader=new Thread(this::loop,"Safi-DNS");reader.start();}
        void submit(byte[] query,TcpDnsProxy.Answer answer){
            if(!alive)return;
            try{workers.execute(() -> {byte[] response=resolver.resolve(query);if(alive)answer.accept(response);});}
            catch(RejectedExecutionException e){if(alive)answer.accept(resolver.overloaded(query));}
        }
        void write(byte[] packet){
            synchronized(outputLock){if(!alive)return;try{output.write(packet);}catch(IOException e){broken();}}
        }
        void broken(){if(alive&&fault.compareAndSet(false,true))main.post(() -> fail(token));}
        void loop(){
            byte[] buffer=new byte[32768];StructPollfd fd=new StructPollfd();fd.fd=tun.getFileDescriptor();fd.events=(short)OsConstants.POLLIN;
            try{
                while(alive){
                    int ready=Os.poll(new StructPollfd[]{fd},500);if(!alive)break;
                    tcp.tick();if(ready==0)continue;
                    if((fd.revents&(OsConstants.POLLERR|OsConstants.POLLHUP|OsConstants.POLLNVAL))!=0)throw new IOException("VPN descriptor closed");
                    if((fd.revents&OsConstants.POLLIN)==0)continue;
                    int n=input.read(buffer);if(n<0)throw new IOException("VPN EOF");
                    IpPacket packet=IpPacket.parse(buffer,n);
                    if(packet==null||packet.destination!=IpPacket.DNS_IP)continue;
                    if(packet.destinationPort!=53){
                        // Reject Android's opportunistic DoT probe quickly so automatic Private DNS falls back to port 53.
                        if(packet.protocol==IpPacket.TCP&&(packet.flags&4)==0){
                            if((packet.flags&16)!=0)write(packet.tcpReply(packet.ack,0,4,0,new byte[0]));
                            else write(packet.tcpReply(0,(packet.seq+packet.payload.length+((packet.flags&2)!=0?1:0)+((packet.flags&1)!=0?1:0))&0xffffffffL,20,0,new byte[0]));
                        }
                        continue;
                    }
                    if(packet.protocol==IpPacket.UDP){
                        submit(packet.payload,answer -> {
                            byte[] data=answer.length>DnsCodec.udpLimit(packet.payload)?DnsCodec.truncated(packet.payload):answer;
                            write(packet.udpReply(data));
                        });
                    }else if(packet.protocol==IpPacket.TCP)tcp.accept(packet);
                }
            }catch(Exception e){broken();}
        }
        public void close(){
            alive=false;resolver.close();workers.shutdownNow();tcp.close();
            if(reader!=null&&Thread.currentThread()!=reader){try{reader.join(700);}catch(InterruptedException e){Thread.currentThread().interrupt();}}
            synchronized(outputLock){try{tun.close();}catch(IOException ignored){}}
        }
    }
}
