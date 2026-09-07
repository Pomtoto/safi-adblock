/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

import android.Manifest;
import android.app.*;
import android.content.*;
import android.content.pm.*;
import android.content.res.ColorStateList;
import android.graphics.*;
import android.graphics.drawable.*;
import android.net.*;
import android.os.*;
import android.provider.Settings;
import android.text.InputType;
import android.view.*;
import android.widget.*;
import java.io.*;
import java.text.Collator;
import java.util.*;
import java.util.concurrent.*;

public final class MainActivity extends Activity {
    private static final int BG=Color.rgb(16,24,23),CARD=Color.rgb(25,35,32),LINE=Color.rgb(44,58,50),
            INK=Color.rgb(245,247,242),MUTED=Color.rgb(157,175,163),LIME=Color.rgb(199,245,138),AMBER=Color.rgb(238,191,121);
    private static final int VPN_REQUEST=10,NOTIFY_REQUEST=11;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private final ExecutorService io=Executors.newSingleThreadExecutor();
    private int tab=0;private boolean updating;private LinearLayout root,body;
    private TextView statusPill,statusTitle,statusDetail,blockedValue,totalValue,sessionLabel,elapsedLabel,dnsTitle,dnsDetail;
    private Button toggle,updateButton;private HeroView hero;
    private final Runnable refresh=new Runnable(){public void run(){refreshDashboard();handler.postDelayed(this,1000);}};
    @Override public void onCreate(Bundle state){
        super.onCreate(state);AppState.init(this);if(state!=null)tab=state.getInt("tab",0);
        getWindow().setStatusBarColor(BG);getWindow().setNavigationBarColor(BG);
        if(Build.VERSION.SDK_INT>=30)getWindow().setDecorFitsSystemWindows(false);
        else getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LAYOUT_STABLE|View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN|View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION);
        render();
    }
    @Override protected void onSaveInstanceState(Bundle out){super.onSaveInstanceState(out);out.putInt("tab",tab);}
    @Override protected void onResume(){super.onResume();handler.removeCallbacks(refresh);handler.post(refresh);}
    @Override protected void onPause(){handler.removeCallbacks(refresh);super.onPause();}
    @Override protected void onDestroy(){handler.removeCallbacksAndMessages(null);io.shutdownNow();super.onDestroy();}
    private int dp(float n){return Math.round(n*getResources().getDisplayMetrics().density);}
    private int side(){return Math.max(20,(int)(getResources().getDisplayMetrics().widthPixels/getResources().getDisplayMetrics().density-560)/2);}
    private LinearLayout vertical(){LinearLayout v=new LinearLayout(this);v.setOrientation(LinearLayout.VERTICAL);return v;}
    private LinearLayout row(){LinearLayout v=new LinearLayout(this);v.setOrientation(LinearLayout.HORIZONTAL);v.setGravity(Gravity.CENTER_VERTICAL);return v;}
    private TextView text(String s,float size,int color,boolean bold){
        TextView v=new TextView(this);v.setText(s);v.setTextSize(size);v.setTextColor(color);
        v.setTypeface(Typeface.create(bold?"sans-serif-medium":"sans-serif",Typeface.NORMAL));
        v.setGravity(Gravity.START);v.setTextDirection(View.TEXT_DIRECTION_FIRST_STRONG);
        v.setLineSpacing(dp(2),1.05f);v.setIncludeFontPadding(true);return v;
    }
    private TextView center(String s,float size,int color,boolean bold){TextView v=text(s,size,color,bold);v.setGravity(Gravity.CENTER);return v;}
    private GradientDrawable shape(int color,int stroke,int radius){GradientDrawable d=new GradientDrawable();d.setColor(color);d.setCornerRadius(dp(radius));if(stroke!=0)d.setStroke(dp(1),stroke);return d;}
    private Drawable ripple(int color,int stroke,int radius){return new RippleDrawable(ColorStateList.valueOf(0x24c7f58a),shape(color,stroke,radius),shape(Color.WHITE,0,radius));}
    private void space(LinearLayout target,int h){View v=new View(this);target.addView(v,new LinearLayout.LayoutParams(1,dp(h)));}
    private void add(LinearLayout parent,View child){parent.addView(child,new LinearLayout.LayoutParams(-1,-2));}
    private Button button(String label,boolean filled){
        Button b=new Button(this);b.setText(label);b.setTextSize(16);b.setAllCaps(false);b.setTextColor(filled?BG:LIME);
        b.setTypeface(Typeface.create("sans-serif-medium",Typeface.NORMAL));b.setPadding(dp(12),dp(8),dp(12),dp(8));
        b.setMinHeight(0);b.setMinimumHeight(dp(52));b.setStateListAnimator(null);b.setBackground(ripple(filled?LIME:CARD,filled?0:LINE,16));return b;
    }
    private LinearLayout card(){LinearLayout c=vertical();c.setPadding(dp(18),dp(16),dp(18),dp(16));c.setBackground(shape(CARD,LINE,22));return c;}
    private void cardAdd(LinearLayout c){add(body,c);space(body,14);}
    private void render(){
        statusPill=null;statusTitle=null;toggle=null;hero=null;updateButton=null;
        root=vertical();root.setBackgroundColor(BG);root.setLayoutDirection(View.LAYOUT_DIRECTION_RTL);
        root.setOnApplyWindowInsetsListener((v,insets)->{
            if(Build.VERSION.SDK_INT>=30){Insets i=insets.getInsets(WindowInsets.Type.systemBars()|WindowInsets.Type.displayCutout());v.setPadding(i.left,i.top,i.right,i.bottom);}
            else v.setPadding(insets.getSystemWindowInsetLeft(),insets.getSystemWindowInsetTop(),insets.getSystemWindowInsetRight(),insets.getSystemWindowInsetBottom());
            return insets;
        });
        setContentView(root);header();
        ScrollView scroll=new ScrollView(this);scroll.setFillViewport(true);scroll.setClipToPadding(false);scroll.setVerticalScrollBarEnabled(false);
        body=vertical();body.setPadding(dp(side()),dp(4),dp(side()),dp(24));scroll.addView(body,new ScrollView.LayoutParams(-1,-2));
        root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
        if(tab==0)dashboard();else if(tab==1)rules();else about();
        bottomNav();root.requestApplyInsets();refreshDashboard();
    }
    private void header(){
        LinearLayout row=row();row.setPadding(dp(side()),dp(14),dp(side()),dp(12));
        Glyph logo=new Glyph("shield",LIME);logo.setPadding(dp(8),dp(8),dp(8),dp(8));logo.setBackground(shape(0xff293a2b,0,14));
        row.addView(logo,new LinearLayout.LayoutParams(dp(46),dp(46)));
        LinearLayout titles=vertical();LinearLayout.LayoutParams titleLp=new LinearLayout.LayoutParams(0,-2,1);titleLp.setMarginStart(dp(12));
        add(titles,text("صافي",25,INK,true));add(titles,text("مساحة أقل للإزعاج",11,MUTED,false));row.addView(titles,titleLp);
        TextView badge=center("بدون روت",11,LIME,true);badge.setPadding(dp(12),dp(6),dp(12),dp(6));badge.setBackground(shape(0xff203023,0,30));row.addView(badge);
        add(root,row);
    }
    private void bottomNav(){
        View line=new View(this);line.setBackgroundColor(LINE);root.addView(line,new LinearLayout.LayoutParams(-1,dp(1)));
        LinearLayout nav=row();nav.setPadding(dp(side()),dp(5),dp(side()),dp(5));
        String[] names={"الحماية","القواعد","حول"},icons={"shield","sliders","info"};
        for(int i=0;i<3;i++){
            final int dest=i;LinearLayout item=vertical();item.setGravity(Gravity.CENTER);item.setPadding(0,dp(7),0,dp(5));
            item.setBackground(ripple(tab==i?0xff203023:BG,0,15));
            Glyph icon=new Glyph(icons[i],tab==i?LIME:MUTED);item.addView(icon,new LinearLayout.LayoutParams(dp(22),dp(22)));
            TextView label=center(names[i],11,tab==i?LIME:MUTED,tab==i);add(item,label);
            item.setContentDescription(names[i]+(tab==i?"، محدد":""));item.setFocusable(true);item.setSelected(tab==i);
            item.setOnClickListener(v->{tab=dest;render();});nav.addView(item,new LinearLayout.LayoutParams(0,dp(64),1));
        }
        add(root,nav);
    }
    private void dashboard(){
        space(body,8);
        LinearLayout badgeRow=row();badgeRow.setGravity(Gravity.CENTER);
        statusPill=center("جاهز للحماية",12,LIME,true);statusPill.setPadding(dp(14),dp(5),dp(14),dp(5));statusPill.setBackground(shape(0xff203023,0,30));
        badgeRow.addView(statusPill);add(body,badgeRow);
        hero=new HeroView();body.addView(hero,new LinearLayout.LayoutParams(-1,dp(174)));
        statusTitle=center("إعلانات أقل. راحة أكثر.",26,INK,true);add(body,statusTitle);space(body,3);
        statusDetail=center("شغّل الحجب للتطبيقات والألعاب، بدون روت.",14,MUTED,false);add(body,statusDetail);space(body,20);
        toggle=button("تشغيل الحماية",true);add(body,toggle);toggle.setOnClickListener(v->toggleProtection());
        space(body,7);add(body,center("VPN محلي فقط • لا يغيّر بلدك",11,MUTED,false));space(body,24);
        LinearLayout session=row();sessionLabel=text("آخر جلسة",12,MUTED,false);session.addView(sessionLabel,new LinearLayout.LayoutParams(0,-2,1));
        elapsedLabel=text("",12,MUTED,false);elapsedLabel.setTextDirection(View.TEXT_DIRECTION_LTR);session.addView(elapsedLabel);add(body,session);space(body,9);
        LinearLayout stats=row();LinearLayout blocked=card(),total=card();blocked.setPadding(dp(16),dp(14),dp(16),dp(14));total.setPadding(dp(16),dp(14),dp(16),dp(14));
        blockedValue=text("0",31,LIME,true);blockedValue.setTextDirection(View.TEXT_DIRECTION_LTR);blockedValue.setGravity(Gravity.RIGHT);add(blocked,blockedValue);add(blocked,text("طلبات محجوبة",12,MUTED,false));
        totalValue=text("0",31,INK,true);totalValue.setTextDirection(View.TEXT_DIRECTION_LTR);totalValue.setGravity(Gravity.RIGHT);add(total,totalValue);add(total,text("طلبات DNS",12,MUTED,false));
        LinearLayout.LayoutParams left=new LinearLayout.LayoutParams(0,-1,1);left.setMarginEnd(dp(10));stats.addView(blocked,left);stats.addView(total,new LinearLayout.LayoutParams(0,-1,1));
        add(body,stats);space(body,14);
        LinearLayout dns=card();LinearLayout line=row();Glyph lock=new Glyph("lock",LIME);line.addView(lock,new LinearLayout.LayoutParams(dp(24),dp(24)));
        dnsTitle=text("DNS مشفّر عند التشغيل",14,INK,true);LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(0,-2,1);lp.setMarginStart(dp(10));line.addView(dnsTitle,lp);add(dns,line);
        space(dns,5);dnsDetail=text("Cloudflare · DNS over HTTPS",12,MUTED,false);dnsDetail.setTextDirection(View.TEXT_DIRECTION_LTR);add(dns,dnsDetail);cardAdd(dns);
        LinearLayout note=card();note.setBackground(shape(0xff26271e,0xff3d3c2a,20));add(note,text("مو كل إعلان يختفي",13,AMBER,true));space(note,3);
        add(note,text("إعلانات يوتيوب وبعض تطبيقات التواصل قد تبقى. اعرف حدود الحجب من صفحة «حول».",12,MUTED,false));
        note.setOnClickListener(v->{tab=2;render();});cardAdd(note);
    }
    private void refreshDashboard(){
        if(tab!=0||toggle==null)return;
        int s=AppState.state;boolean active=s==AppState.ON,busy=AppState.busy();
        statusPill.setText(active?"●  الحماية تعمل":busy?"جارٍ التجهيز…":s==AppState.ERROR?"يلزم إعادة المحاولة":"جاهز للحماية");
        statusTitle.setText(active?"إنترنت أهدأ.":busy?"لحظات ونجهّز الحماية…":"إعلانات أقل. راحة أكثر.");
        statusDetail.setText(s==AppState.ERROR?AppState.message:active?"نحجب نطاقات الإعلانات والتتبّع على جهازك.":busy?"يجري تطبيق إعدادات اتصال VPN المحلي.":"شغّل الحجب للتطبيقات والألعاب، بدون روت.");
        statusDetail.setTextColor(s==AppState.ERROR?AMBER:MUTED);
        toggle.setText(active?"إيقاف الحماية":s==AppState.STOPPING?"جارٍ الإيقاف…":busy?"جارٍ التشغيل…":"تشغيل الحماية");
        toggle.setEnabled(!busy);toggle.setAlpha(busy?0.6f:1f);toggle.setTextColor(active?LIME:BG);toggle.setBackground(ripple(active?CARD:LIME,active?LINE:0,16));
        hero.setActive(active);
        blockedValue.setText(number(AppState.blocked.get()));totalValue.setText(number(AppState.requests.get()));
        sessionLabel.setText(active||busy?"هذه الجلسة • طلبات DNS، مو عدد الإعلانات":"آخر جلسة • عدادات محفوظة على جهازك");
        elapsedLabel.setText(active?duration((SystemClock.elapsedRealtime()-AppState.startedAt)/1000):"");
        if(active&&AppState.lastFailure>AppState.lastSuccess){dnsTitle.setText("تعذّر الوصول إلى DNS");dnsTitle.setTextColor(AMBER);dnsDetail.setText("افحص الإنترنت، أو أوقف الحماية إذا توقف الاتصال.");}
        else{dnsTitle.setText(active?(AppState.lastSuccess>0?"اتصال DNS المشفّر يعمل":"بانتظار أول طلب DNS مسموح"):"DNS مشفّر عند التشغيل");dnsTitle.setTextColor(INK);dnsDetail.setText("Cloudflare · DNS over HTTPS");}
    }
    private String number(long n){return String.format(Locale.US,"%,d",n);}
    private String duration(long sec){sec=Math.max(0,sec);return sec>=3600?String.format(Locale.US,"%d:%02d:%02d",sec/3600,(sec/60)%60,sec%60):String.format(Locale.US,"%02d:%02d",sec/60,sec%60);}
    private void pageTitle(String title,String subtitle){space(body,18);add(body,text(title,28,INK,true));space(body,5);add(body,text(subtitle,14,MUTED,false));space(body,24);}
    private void rules(){
        pageTitle("الحجب على مزاجك.","خفّف الإعلانات، واستثنِ اللي تحتاجه.");
        LinearLayout list=card();add(list,text("قائمة الحجب المحلية",16,INK,true));space(list,8);
        TextView count=text(number(AppPrefs.count(this))+"  نطاق",27,LIME,true);add(list,count);
        add(list,text("HaGeZi Multi LIGHT",13,INK,true));space(list,4);
        add(list,text("قائمة خفيفة للإعلانات والتتبّع الشائع. تبقى مضمّنة وتعمل بدون تحميل أولي.",12,MUTED,false));
        space(list,9);TextView ver=text("الإصدار: "+AppPrefs.version(this),11,MUTED,false);add(list,ver);space(list,14);
        updateButton=button(updating?"جارٍ التحديث…":"تحديث القائمة",false);updateButton.setEnabled(!updating);add(list,updateButton);updateButton.setOnClickListener(v->updateList());cardAdd(list);
        setting("نطاقات مسموحة","استثناء مواقع من الحجب • "+userCount("allowed"),"check",()->editDomains("allowed",true));
        setting("حجب يدوي","أضف نطاق إعلان غير محجوب • "+userCount("custom"),"plus",()->editDomains("custom",false));
        setting("التطبيقات المستثناة","بدون فلترة DNS • "+AppPrefs.excluded(this).size()+" تطبيق","apps",this::chooseApps);
        setting("إعداد DNS الخاص","راجع هذا الخيار إذا تجاوز جهازك الحجب.","sliders",this::openDnsSettings);
        add(body,text("السماح له أولوية على الحجب. كل قاعدة تشمل النطاق ونطاقاته الفرعية. حفظ التغييرات يعيد اتصال الحماية إذا كان شغّالًا.",12,MUTED,false));
    }
    private int userCount(String key){try{return DomainRules.parseUser(AppPrefs.get(this).getString(key,"")).size();}catch(Exception e){return 0;}}
    private void setting(String title,String subtitle,String icon,Runnable action){
        LinearLayout c=card(),r=row();Glyph glyph=new Glyph(icon,LIME);r.addView(glyph,new LinearLayout.LayoutParams(dp(26),dp(26)));
        LinearLayout texts=vertical();add(texts,text(title,15,INK,true));add(texts,text(subtitle,12,MUTED,false));LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(0,-2,1);lp.setMarginStart(dp(14));r.addView(texts,lp);
        TextView chevron=center("‹",26,MUTED,false);r.addView(chevron,new LinearLayout.LayoutParams(dp(22),-2));add(c,r);
        c.setBackground(ripple(CARD,LINE,22));c.setFocusable(true);c.setOnClickListener(v->action.run());cardAdd(c);
    }
    private void about(){
        pageTitle("أقل إزعاج.\nبلا صلاحيات زائدة.","صافي 1.0 • للأندرويد 8 والأحدث");
        LinearLayout privacy=card();add(privacy,text("خصوصيتك أولًا",18,LIME,true));space(privacy,8);
        add(privacy,text("صافي ينشئ VPN محلي لتصفية طلبات DNS فقط. ما يقرأ محتوى الرسائل أو صفحات HTTPS، وما يغيّر عنوان IP أو بلدك.\n\nالنطاقات المسموحة تُرسل مشفّرة إلى Cloudflare لحلّ DNS. لا يوجد سجل تصفح محفوظ أو تحليلات داخل التطبيق؛ فقط إعدادات وعدادات على جهازك، وذاكرة DNS مؤقتة أثناء التشغيل.",14,MUTED,false));
        space(privacy,14);Button policy=button("سياسة خصوصية مزوّد DNS",false);add(privacy,policy);policy.setOnClickListener(v->external("https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/"));cardAdd(privacy);
        LinearLayout limits=card();add(limits,text("شنو يگدر يحجب؟",18,AMBER,true));space(limits,9);
        add(limits,text("• يحجب مصادر إعلانات وتتبّع منفصلة في كثير من التطبيقات والألعاب. قد تبقى مساحة فارغة مكان الإعلان.\n\n• لا يضمن إزالة إعلانات يوتيوب أو الإعلانات التي تستخدم نفس نطاق المحتوى. DNS المشفّر داخل التطبيق، أو الاتصال بعنوان IP مباشر، قد يتجاوز الحجب.\n\n• بعض الألعاب تحتاج إعلانًا لمنح مكافأة؛ الحجب قد يمنع المكافأة. استثنِ التطبيق إذا تأثر.\n\n• لا يعمل مع VPN آخر في الوقت نفسه، ولا تستخدم معه «حظر الاتصالات بدون VPN». شغّله يدويًا بعد إعادة تشغيل الهاتف.\n\n• لا يحتاج روت، ويعمل أيضًا على الأجهزة المروّتة بنفس الطريقة، بدون طلب صلاحيات الروت.",14,MUTED,false));cardAdd(limits);
        setting("إذا توقف موقع أو تطبيق","جرّب استثناءه من القواعد، أو أوقف الحماية.","info",()->{tab=1;render();});
        LinearLayout legal=card();add(legal,text("مفتوح المصدر • GPL-3.0",15,INK,true));space(legal,5);
        add(legal,text("© 2026 مساهمو صافي. هذه نسخة تجريبية تُقدَّم بلا ضمان. يحق لك نسخها وتعديلها وإعادة توزيعها وفق GPL-3.0. قائمة HaGeZi تحت الرخصة نفسها. التطبيق مستقل وغير تابع لـ Cloudflare أو HaGeZi.",12,MUTED,false));
        space(legal,13);Button license=button("عرض الترخيص",false);add(legal,license);license.setOnClickListener(v->showLicense());
        space(legal,8);Button source=button("مصدر قائمة الحجب",false);add(legal,source);source.setOnClickListener(v->external("https://github.com/hagezi/dns-blocklists"));cardAdd(legal);
        add(body,center("صافي • DNS محلي، بدون روت أو شهادة",11,MUTED,false));
    }
    private void toggleProtection(){
        if(AppState.busy())return;
        if(AppState.state==AppState.ON){startService(new Intent(this,ShieldVpnService.class).setAction(ShieldVpnService.STOP));refreshDashboard();return;}
        if(!AppPrefs.get(this).getBoolean("disclosure",false)){
            new AlertDialog.Builder(this).setTitle("قبل ما تشغّل صافي")
                    .setMessage("سيطلب أندرويد إذن VPN. الاتصال محلي لتصفية DNS فقط، مو VPN لتغيير البلد.\n\nأسماء النطاقات المسموحة تُرسل مشفّرة إلى Cloudflare (1.1.1.1). التطبيق ما يسجّل أسماء المواقع ولا يقرأ المحتوى. تحديث القائمة عند طلبك يتصل بـ GitHub.\n\nما يشتغل مع VPN آخر، وما يضمن حجب كل إعلان. تگدر توقفه بأي وقت من التطبيق أو الإشعار.")
                    .setNegativeButton("مو هسه",null).setPositiveButton("موافق، متابعة",(d,w)->{AppPrefs.get(this).edit().putBoolean("disclosure",true).apply();checkPrivateDns();}).show();
        }else checkPrivateDns();
    }
    private void checkPrivateDns(){
        String mode=null;try{mode=Settings.Global.getString(getContentResolver(),"private_dns_mode");}catch(SecurityException ignored){}
        if("hostname".equals(mode)){
            new AlertDialog.Builder(this).setTitle("راجع DNS الخاص")
                    .setMessage("DNS الخاص مضبوط على مزوّد محدد، وهذا ممكن يتجاوز الحجب. اجعله «تلقائي» أو «إيقاف»، ثم شغّل صافي. إذا بقيت الإعلانات، عطّل DNS الآمن داخل المتصفح أيضًا.")
                    .setPositiveButton("فتح الإعدادات",(d,w)->openDnsSettings()).setNegativeButton("تشغيل مع التنبيه",(d,w)->requestVpn()).setNeutralButton("إلغاء",null).show();
        }else requestVpn();
    }
    private void requestVpn(){
        if(Build.VERSION.SDK_INT>=33&&checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)!=PackageManager.PERMISSION_GRANTED&&!AppPrefs.get(this).getBoolean("notification_asked",false)){
            AppPrefs.get(this).edit().putBoolean("notification_asked",true).apply();requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},NOTIFY_REQUEST);return;
        }
        Intent consent=android.net.VpnService.prepare(this);
        if(consent!=null)startActivityForResult(consent,VPN_REQUEST);else startProtection();
    }
    @Override public void onRequestPermissionsResult(int request,String[] permissions,int[] results){
        super.onRequestPermissionsResult(request,permissions,results);if(request==NOTIFY_REQUEST)requestVpn();
    }
    @Override protected void onActivityResult(int request,int result,Intent data){
        super.onActivityResult(request,result,data);
        if(request==VPN_REQUEST){if(result==RESULT_OK)startProtection();else toast("لم يتم التشغيل؛ إذن VPN ضروري للحجب.");}
    }
    private void startProtection(){
        try{startForegroundService(new Intent(this,ShieldVpnService.class).setAction(ShieldVpnService.START));}
        catch(RuntimeException e){toast("تعذّر بدء الخدمة. افتح التطبيق مجددًا وحاول.");}
        handler.postDelayed(this::refreshDashboard,150);
    }
    private void changed(){
        if(AppState.state==AppState.ON||AppState.state==AppState.STARTING){
            startForegroundService(new Intent(this,ShieldVpnService.class).setAction(ShieldVpnService.RESTART));toast("تم الحفظ. يعاد اتصال الحماية لتطبيق التغييرات.");
        }else toast("تم الحفظ.");
        render();
    }
    private void editDomains(String key,boolean allow){
        LinearLayout content=vertical();content.setPadding(dp(22),dp(10),dp(22),0);content.setLayoutDirection(View.LAYOUT_DIRECTION_RTL);
        add(content,text("اكتب نطاقًا واحدًا بكل سطر، بدون https أو مسارات. يشمل النطاق وفروعه."+(allow?" السماح يتجاوز الحجب.":""),13,MUTED,false));space(content,12);
        EditText edit=new EditText(this);edit.setTextColor(INK);edit.setHintTextColor(MUTED);edit.setTextSize(15);edit.setMinLines(4);edit.setMaxLines(9);
        edit.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_FLAG_MULTI_LINE|InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
        edit.setTypeface(Typeface.MONOSPACE);edit.setGravity(Gravity.TOP|Gravity.LEFT);edit.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);edit.setTextDirection(View.TEXT_DIRECTION_LTR);
        edit.setHint("example.com\nads.example.org");edit.setText(AppPrefs.get(this).getString(key,""));add(content,edit);
        AlertDialog dialog=new AlertDialog.Builder(this).setTitle(allow?"نطاقات مسموحة":"حجب يدوي").setView(content).setNegativeButton("إلغاء",null).setPositiveButton("حفظ",null).create();
        dialog.setOnShowListener(v->dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(b->{
            try{Set<String> entries=DomainRules.parseUser(edit.getText().toString());AppPrefs.get(this).edit().putString(key,DomainRules.userText(entries)).apply();dialog.dismiss();changed();}
            catch(IllegalArgumentException e){edit.setError(e.getMessage());}
        }));dialog.show();
    }
    private void chooseApps(){
        toast("جارٍ قراءة قائمة التطبيقات…");
        io.execute(()->{
            PackageManager pm=getPackageManager();Map<String,String> apps=new HashMap<>();
            Intent launcher=new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
            for(ResolveInfo info:pm.queryIntentActivities(launcher,0)){
                if(info.activityInfo==null||info.activityInfo.packageName.equals(getPackageName()))continue;
                String pkg=info.activityInfo.packageName;CharSequence label=info.loadLabel(pm);apps.put(pkg,label==null?pkg:label.toString());
            }
            List<String> packages=new ArrayList<>(apps.keySet());Collator collator=Collator.getInstance(new Locale("ar"));packages.sort((a,b)->collator.compare(apps.get(a),apps.get(b)));
            runOnUiThread(()->{
                if(isFinishing()||isDestroyed())return;
                if(packages.isEmpty()){toast("ما ظهرت تطبيقات قابلة للاستثناء.");return;}
                Set<String> selected=AppPrefs.excluded(this);String[] names=new String[packages.size()];boolean[] checked=new boolean[packages.size()];
                for(int i=0;i<names.length;i++){names[i]=apps.get(packages.get(i))+"\n"+packages.get(i);checked[i]=selected.contains(packages.get(i));}
                new AlertDialog.Builder(this).setTitle("تطبيقات بدون حجب")
                        .setMultiChoiceItems(names,checked,(d,i,value)->{if(value)selected.add(packages.get(i));else selected.remove(packages.get(i));})
                        .setNegativeButton("إلغاء",null).setPositiveButton("حفظ",(d,w)->{AppPrefs.get(this).edit().putStringSet("excluded_apps",selected).apply();changed();}).show();
            });
        });
    }
    private void updateList(){
        if(updating)return;updating=true;if(updateButton!=null){updateButton.setText("جارٍ التحديث…");updateButton.setEnabled(false);}
        Context app=getApplicationContext();
        io.execute(()->{
            String error=null;
            try{AppPrefs.updateList(app);}catch(Exception e){error="تعذّر التحديث. بقيت قائمة الحجب الحالية بدون تغيير؛ تأكد من الإنترنت وجرّب لاحقًا.";}
            final String result=error;
            runOnUiThread(()->{updating=false;if(isFinishing()||isDestroyed())return;if(result==null)changed();else{toast(result);render();}});
        });
    }
    private void openDnsSettings(){
        try{startActivity(new Intent("android.settings.PRIVATE_DNS_SETTINGS"));}
        catch(ActivityNotFoundException e){try{startActivity(new Intent(Settings.ACTION_WIRELESS_SETTINGS));}catch(ActivityNotFoundException ignored){toast("افتح إعدادات الشبكة وابحث عن DNS الخاص.");}}
    }
    private void external(String url){try{startActivity(new Intent(Intent.ACTION_VIEW,Uri.parse(url)));}catch(ActivityNotFoundException e){toast("ماكو متصفح مثبت لفتح الرابط.");}}
    private void showLicense(){
        try{
            ByteArrayOutputStream out=new ByteArrayOutputStream();try(InputStream in=getAssets().open("GPL-3.0.txt")){byte[] b=new byte[4096];int n;while((n=in.read(b))!=-1)out.write(b,0,n);}
            ScrollView scroll=new ScrollView(this);TextView t=text(out.toString("UTF-8"),12,INK,false);t.setTextIsSelectable(true);t.setTextDirection(View.TEXT_DIRECTION_LTR);t.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);t.setPadding(dp(20),dp(8),dp(20),dp(16));scroll.addView(t);
            new AlertDialog.Builder(this).setTitle("GNU GPL v3").setView(scroll).setPositiveButton("إغلاق",null).show();
        }catch(IOException e){toast("الترخيص مرفق مع المشروع: GPL-3.0.");}
    }
    private void toast(String s){Toast.makeText(this,s,Toast.LENGTH_LONG).show();}
    @Override public void onBackPressed(){if(tab!=0){tab=0;render();}else super.onBackPressed();}

    private final class HeroView extends View {
        final Paint paint=new Paint(Paint.ANTI_ALIAS_FLAG);boolean active;
        HeroView(){super(MainActivity.this);setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);}
        void setActive(boolean value){if(active!=value){active=value;invalidate();}}
        @Override protected void onDraw(Canvas c){
            super.onDraw(c);c.save();c.translate(getWidth()/2f,getHeight()/2f);float unit=dp(1);c.scale(unit,unit);
            paint.setStyle(Paint.Style.STROKE);paint.setStrokeWidth(1);paint.setColor(LINE);c.drawCircle(0,0,75,paint);c.drawCircle(0,0,60,paint);
            paint.setColor(0xff223528);paint.setStyle(Paint.Style.FILL);c.drawCircle(0,0,48,paint);
            paint.setColor(active?LIME:0xff82aa69);c.drawCircle(65,-37,3.5f,paint);c.drawCircle(-67,34,2.5f,paint);
            paint.setColor(0xff536947);c.drawCircle(16,73,2,paint);
            Path shield=new Path();shield.moveTo(0,-38);shield.lineTo(31,-25);shield.lineTo(31,-1);shield.cubicTo(31,23,13,36,0,44);shield.cubicTo(-13,36,-31,23,-31,-1);shield.lineTo(-31,-25);shield.close();
            paint.setColor(active?LIME:0xffb4d995);c.drawPath(shield,paint);
            paint.setStyle(Paint.Style.STROKE);paint.setStrokeCap(Paint.Cap.ROUND);paint.setStrokeJoin(Paint.Join.ROUND);paint.setStrokeWidth(5);paint.setColor(BG);
            Path check=new Path();check.moveTo(-13,0);check.lineTo(-3,10);check.lineTo(16,-12);c.drawPath(check,paint);c.restore();
        }
    }
    private final class Glyph extends View {
        final String type;final int color;final Paint p=new Paint(Paint.ANTI_ALIAS_FLAG);
        Glyph(String type,int color){super(MainActivity.this);this.type=type;this.color=color;setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);}
        @Override protected void onDraw(Canvas c){
            super.onDraw(c);float w=getWidth()-getPaddingLeft()-getPaddingRight(),h=getHeight()-getPaddingTop()-getPaddingBottom();
            float scale=Math.min(w,h)/24f;c.save();c.translate(getPaddingLeft()+(w-24*scale)/2,getPaddingTop()+(h-24*scale)/2);c.scale(scale,scale);
            p.setColor(color);p.setStrokeWidth(1.8f);p.setStrokeCap(Paint.Cap.ROUND);p.setStrokeJoin(Paint.Join.ROUND);p.setStyle(Paint.Style.STROKE);
            if(type.equals("shield")){Path s=new Path();s.moveTo(12,2);s.lineTo(21,6);s.lineTo(21,12);s.cubicTo(21,17,16,21,12,23);s.cubicTo(8,21,3,17,3,12);s.lineTo(3,6);s.close();c.drawPath(s,p);c.drawLine(8,12,11,15,p);c.drawLine(11,15,17,9,p);}
            else if(type.equals("info")){c.drawCircle(12,12,9,p);c.drawLine(12,11,12,17,p);c.drawPoint(12,7,p);}
            else if(type.equals("lock")){c.drawRoundRect(5,10,19,21,3,3,p);c.drawArc(8,2,16,15,180,180,false,p);c.drawLine(12,14,12,17,p);}
            else if(type.equals("sliders")){for(int y:new int[]{6,12,18})c.drawLine(3,y,21,y,p);p.setStyle(Paint.Style.FILL);c.drawCircle(8,6,2.7f,p);c.drawCircle(16,12,2.7f,p);c.drawCircle(10,18,2.7f,p);}
            else if(type.equals("check")){c.drawCircle(12,12,9,p);c.drawLine(7,12,11,16,p);c.drawLine(11,16,17,8,p);}
            else if(type.equals("plus")){c.drawCircle(12,12,9,p);c.drawLine(7,12,17,12,p);c.drawLine(12,7,12,17,p);}
            else if(type.equals("apps")){for(int x:new int[]{3,14})for(int y:new int[]{3,14})c.drawRoundRect(x,y,x+7,y+7,1.5f,1.5f,p);}
            c.restore();
        }
    }
}
