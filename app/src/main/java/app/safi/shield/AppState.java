/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

import android.content.*;
import java.util.concurrent.atomic.AtomicLong;

public final class AppState {
    public static final int OFF=0,STARTING=1,ON=2,STOPPING=3,ERROR=4;
    public static volatile int state=OFF;
    public static volatile String message="";
    public static volatile long startedAt,lastSuccess,lastFailure;
    public static final AtomicLong requests=new AtomicLong(),blocked=new AtomicLong(),errors=new AtomicLong();
    private static boolean initialized;
    public static synchronized void init(Context c){
        if(initialized)return;initialized=true;SharedPreferences p=AppPrefs.get(c);
        requests.set(p.getLong("requests",0));blocked.set(p.getLong("blocked",0));errors.set(p.getLong("errors",0));
    }
    public static void reset(){requests.set(0);blocked.set(0);errors.set(0);lastSuccess=0;lastFailure=0;startedAt=android.os.SystemClock.elapsedRealtime();message="";}
    public static void save(Context c){AppPrefs.get(c).edit().putLong("requests",requests.get()).putLong("blocked",blocked.get()).putLong("errors",errors.get()).apply();}
    public static boolean busy(){return state==STARTING||state==STOPPING;}
}
