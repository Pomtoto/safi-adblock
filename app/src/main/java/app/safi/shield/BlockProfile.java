/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

/** Closed set: no user-controlled file names or remote URLs. */
public enum BlockProfile {
    LIGHT("light","خفيف","HaGeZi Multi LIGHT","light-onlydomains.txt",36608,"2026.0907.0809.33"),
    NORMAL("normal","أوسع","HaGeZi Multi NORMAL","multi-onlydomains.txt",191639,"2026.0907.0805.53");
    public final String id,label,title,upstreamFile,baseVersion;public final int baseCount;
    BlockProfile(String id,String label,String title,String file,int count,String version){
        this.id=id;this.label=label;this.title=title;upstreamFile=file;baseCount=count;baseVersion=version;
    }
    public String asset(){return "hagezi-"+id+".txt";}
    public String url(){return "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/"+upstreamFile;}
    public static BlockProfile from(String id){return "normal".equals(id)?NORMAL:LIGHT;}
}
