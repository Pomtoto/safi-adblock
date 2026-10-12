/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

import android.content.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicBoolean;

/** Process-wide runtime state for the dashboard, the notification and the quick-settings tile. */
public final class AppState {
    public static final int OFF=0,STARTING=1,ON=2,STOPPING=3,ERROR=4;
    public static volatile int state=OFF;
    public static volatile String message="";
    public static volatile long startedAt,lastSuccess,lastFailure;
    public static volatile long lastLatency;
    public static volatile int openEndpoints;
    /** Android's "block connections without VPN" is on: everything outside our DNS route will be cut. */
    public static volatile boolean lockdown;
    public static final AtomicLong requests=new AtomicLong(),blocked=new AtomicLong(),errors=new AtomicLong(),coalesced=new AtomicLong();
    public static final DiagnosticRecorder diagnostics=new DiagnosticRecorder(android.os.SystemClock::elapsedRealtime);
    public static final AtomicBoolean listUpdating=new AtomicBoolean();
    private static boolean initialized;
    public static synchronized void init(Context c){
        if(initialized)return;initialized=true;SharedPreferences p=AppPrefs.get(c);
        requests.set(p.getLong("requests",0));blocked.set(p.getLong("blocked",0));errors.set(p.getLong("errors",0));
    }
    public static void reset(){
        requests.set(0);blocked.set(0);errors.set(0);coalesced.set(0);
        lastSuccess=0;lastFailure=0;lastLatency=0;openEndpoints=0;message="";
        startedAt=android.os.SystemClock.elapsedRealtime();
    }
    public static void save(Context c){
        AppPrefs.get(c).edit().putLong("requests",requests.get()).putLong("blocked",blocked.get()).putLong("errors",errors.get()).apply();
    }
    public static boolean busy(){return state==STARTING||state==STOPPING;}
    /** Human-readable upstream state, used by the dashboard and the notification. */
    public static String upstreamState(){
        if(openEndpoints>0)return "تعذّر الوصول إلى مزوّد DNS";
        if(lastFailure>lastSuccess)return "تعذّر الوصول إلى مزوّد DNS";
        if(lastSuccess>0&&lastLatency>0)return "آخر رد "+lastLatency+" ms";
        if(lastSuccess>0)return "اتصال DNS المشفّر يعمل";
        return "بانتظار أول طلب DNS مسموح";
    }
}
