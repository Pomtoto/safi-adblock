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
    public static SharedPreferences get(Context c){return c.getSharedPreferences("safi",Context.MODE_PRIVATE);}
    public static BlockProfile profile(Context c){return BlockProfile.from(get(c).getString("profile","light"));}
    public static int count(Context c){return count(c,profile(c));}
    public static int count(Context c,BlockProfile mode){
        SharedPreferences p=get(c);int legacy=mode==BlockProfile.LIGHT?p.getInt("list_count",mode.baseCount):mode.baseCount;
        return p.getInt("list_count_"+mode.id,legacy);
    }
    public static String version(Context c){return version(c,profile(c));}
    public static String version(Context c,BlockProfile mode){
        SharedPreferences p=get(c);String legacy=mode==BlockProfile.LIGHT?p.getString("list_version",mode.baseVersion):mode.baseVersion;
        return p.getString("list_version_"+mode.id,legacy);
    }
    public static DomainRules loadRules(Context c)throws IOException{
        BlockProfile mode=profile(c);Set<String> domains;
        AtomicFile file=new AtomicFile(new File(c.getFilesDir(),mode.asset()));
        try{domains=DomainRules.readList(file.openRead());}
        catch(IOException e){
            domains=DomainRules.readList(c.getAssets().open(mode.asset()));
            get(c).edit().putString("list_version_"+mode.id,mode.baseVersion).apply();
        }
        SharedPreferences p=get(c);p.edit().putInt("list_count_"+mode.id,domains.size()).apply();
        try{return new DomainRules(domains,DomainRules.parseUser(p.getString("allowed","")),DomainRules.parseUser(p.getString("custom","")));}
        catch(IllegalArgumentException e){throw new IOException("قواعد المستخدم غير صالحة",e);}
    }
    public static Set<String> excluded(Context c){return new HashSet<>(get(c).getStringSet("excluded_apps",Collections.emptySet()));}
    /** Update the explicitly selected profile; a later UI selection cannot redirect this write. */
    public static int updateList(Context c,BlockProfile mode)throws IOException{
        HttpsURLConnection conn=(HttpsURLConnection)new URL(mode.url()).openConnection();byte[] data;
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
        AtomicFile target=new AtomicFile(new File(c.getFilesDir(),mode.asset()));FileOutputStream stream=null;
        try{stream=target.startWrite();stream.write(data);target.finishWrite(stream);}
        catch(IOException e){if(stream!=null)target.failWrite(stream);throw e;}
        get(c).edit().putInt("list_count_"+mode.id,checked.size()).putString("list_version_"+mode.id,version).apply();return checked.size();
    }
}
