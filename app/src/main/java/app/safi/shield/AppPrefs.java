/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

import android.content.*;
import android.util.AtomicFile;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.net.ssl.HttpsURLConnection;

public final class AppPrefs {
    public static final String LIST_URL="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt";
    public static SharedPreferences get(Context context){return context.getSharedPreferences("safi",Context.MODE_PRIVATE);}
    public static int count(Context c){return get(c).getInt("list_count",36608);}
    public static String version(Context c){return get(c).getString("list_version","2026.0907.0809.33");}
    public static DomainRules loadRules(Context c)throws IOException{
        Set<String> domains;
        AtomicFile file=new AtomicFile(new File(c.getFilesDir(),"hagezi-light.txt"));
        try{domains=DomainRules.readList(file.openRead());}
        catch(IOException e){domains=DomainRules.readList(c.getAssets().open("hagezi-light.txt"));}
        SharedPreferences p=get(c);
        get(c).edit().putInt("list_count",domains.size()).apply();
        try{return new DomainRules(domains,DomainRules.parseUser(p.getString("allowed","")),DomainRules.parseUser(p.getString("custom","")));}
        catch(IllegalArgumentException e){throw new IOException("قواعد المستخدم غير صالحة",e);}
    }
    public static Set<String> excluded(Context c){return new HashSet<>(get(c).getStringSet("excluded_apps",Collections.emptySet()));}
    /** Explicit, user-triggered update only. Old file survives incomplete downloads. */
    public static int updateList(Context c)throws IOException{
        HttpsURLConnection conn=(HttpsURLConnection)new URL(LIST_URL).openConnection();
        byte[] data;
        try{
            conn.setConnectTimeout(10000);conn.setReadTimeout(15000);conn.setInstanceFollowRedirects(false);conn.setUseCaches(false);
            if(conn.getResponseCode()!=200)throw new IOException("تعذّر تحميل القائمة؛ بقيت القائمة الحالية");
            ByteArrayOutputStream out=new ByteArrayOutputStream();
            try(InputStream in=conn.getInputStream()){
                byte[] b=new byte[8192];int n;
                while((n=in.read(b))!=-1){if(out.size()+n>6*1024*1024)throw new IOException("حجم قائمة غير متوقع");out.write(b,0,n);}
            }
            data=out.toByteArray();
        }finally{conn.disconnect();}
        Set<String> checked=DomainRules.readList(new ByteArrayInputStream(data));
        String text=new String(data,StandardCharsets.UTF_8),version="محدّثة";
        for(String line:text.split("\n",30))if(line.startsWith("# Version:")){version=line.substring(10).trim();break;}
        AtomicFile target=new AtomicFile(new File(c.getFilesDir(),"hagezi-light.txt"));FileOutputStream stream=null;
        try{stream=target.startWrite();stream.write(data);target.finishWrite(stream);}
        catch(IOException e){if(stream!=null)target.failWrite(stream);throw e;}
        get(c).edit().putInt("list_count",checked.size()).putString("list_version",version).apply();return checked.size();
    }
}
