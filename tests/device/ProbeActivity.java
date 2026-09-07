/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.probe;
import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.*;
import java.net.*;
import java.io.*;
import app.safi.shield.DnsCodec;

/** Separate UID: an actual client of the VPN, not an in-process rules-only test. */
public final class ProbeActivity extends Activity {
    TextView text;StringBuilder results=new StringBuilder();int passed,failed;
    protected void onCreate(Bundle b){super.onCreate(b);text=new TextView(this);text.setTextSize(15);text.setTextColor(0xff202020);text.setPadding(20,30,20,30);ScrollView scroll=new ScrollView(this);scroll.setBackgroundColor(-1);scroll.addView(text);setContentView(scroll);new Thread(this::run).start();}
    void report(String s){Log.i("SafiProbe",s);results.append(s).append('\n');runOnUiThread(()->text.setText(results.toString()));}
    interface Test{void check()throws Exception;}
    void test(String label,Test t){try{t.check();passed++;report("PASS "+label);}catch(Exception|AssertionError e){failed++;report("FAIL "+label+": "+e.getClass().getSimpleName()+" "+e.getMessage());}}
    void require(boolean ok,String reason){if(!ok)throw new AssertionError(reason);}
    byte[] udp(String host,int type)throws Exception{
        byte[] q=DnsCodec.query(host,type,2222);try(DatagramSocket socket=new DatagramSocket()){
            socket.setSoTimeout(25000);socket.connect(InetAddress.getByName("10.111.222.2"),53);socket.send(new DatagramPacket(q,q.length));byte[] b=new byte[2048];DatagramPacket p=new DatagramPacket(b,b.length);socket.receive(p);byte[] reply=java.util.Arrays.copyOf(b,p.getLength());DnsCodec.validateResponse(q,reply);return reply;
        }
    }
    byte[] tcp(String host,int type)throws Exception{
        byte[] q=DnsCodec.query(host,type,3333);try(Socket socket=new Socket()){
            socket.connect(new InetSocketAddress("10.111.222.2",53),25000);socket.setSoTimeout(25000);DataOutputStream out=new DataOutputStream(socket.getOutputStream());out.writeShort(q.length);out.write(q);out.flush();DataInputStream in=new DataInputStream(socket.getInputStream());int size=in.readUnsignedShort();byte[] reply=new byte[size];in.readFully(reply);DnsCodec.validateResponse(q,reply);return reply;
        }
    }
    void run(){
        report("Safi device probe — separate application UID");
        if(getIntent().getBooleanExtra("bypass",false)){
            test("system DNS works without filtering",()->require(InetAddress.getAllByName("pagead2.googlesyndication.com").length>0,"ad domain should resolve"));
        }else{
            test("UDP A blocked locally",()->require((DnsCodec.u16(udp("pagead2.googlesyndication.com",1),2)&15)==3,"expected NXDOMAIN"));
            test("UDP AAAA blocked locally",()->require((DnsCodec.u16(udp("pagead2.googlesyndication.com",28),2)&15)==3,"expected NXDOMAIN"));
            test("UDP allowed domain via DoH",()->{byte[] r=udp("example.com",1);require((DnsCodec.u16(r,2)&15)==0&&DnsCodec.u16(r,6)>0,"expected answers");});
            test("TCP blocked domain",()->require((DnsCodec.u16(tcp("pagead2.googlesyndication.com",1),2)&15)==3,"expected NXDOMAIN"));
            test("TCP allowed domain",()->{byte[] r=tcp("example.com",1);require((DnsCodec.u16(r,2)&15)==0&&DnsCodec.u16(r,6)>0,"expected answers");});
            test("TCP DNSKEY records",()->{byte[] r=tcp("org",48);require((DnsCodec.u16(r,2)&15)==0&&DnsCodec.u16(r,6)>0,"expected DNSKEY answers");report("DNSKEY response bytes: "+r.length);});
            test("Android system resolver blocks ads",()->{boolean blocked=false;try{InetAddress.getAllByName("pagead2.googlesyndication.com");}catch(UnknownHostException e){blocked=true;}require(blocked,"ad domain unexpectedly resolved");});
            test("Android system resolver allows normal domain",()->require(InetAddress.getAllByName("example.com").length>0,"normal domain failed"));
        }
        report("DEVICE TESTS COMPLETE: "+passed+" passed, "+failed+" failed");
    }
}
