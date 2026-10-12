/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

import android.content.*;
import android.util.AtomicFile;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import android.content.pm.PackageManager;
import java.util.*;

/** Stored settings and list files. Nothing here is network-facing except the two explicit
 *  user-triggered downloads: the profile list and the optional extra list URL. */
public final class AppPrefs {
    private static final int MAX_LIST_BYTES = 16 * 1024 * 1024;
    private static final String CUSTOM_FILE = "custom-list.txt";

    public static SharedPreferences get(Context c) { return c.getSharedPreferences("safi", Context.MODE_PRIVATE); }

    public static BlockProfile profile(Context c) { return BlockProfile.from(get(c).getString("profile", "light")); }
    public static DnsProvider provider(Context c) { return DnsProvider.from(get(c).getString("provider", DnsProvider.CLOUDFLARE.id)); }

    public static int count(Context c) { return count(c, profile(c)); }
    public static int count(Context c, BlockProfile mode) {
        SharedPreferences p = get(c);
        int legacy = mode == BlockProfile.LIGHT ? p.getInt("list_count", mode.baseCount) : mode.baseCount;
        return p.getInt("list_count_" + mode.id, legacy);
    }
    public static String version(Context c) { return version(c, profile(c)); }
    public static String version(Context c, BlockProfile mode) {
        SharedPreferences p = get(c);
        String legacy = mode == BlockProfile.LIGHT ? p.getString("list_version", mode.baseVersion) : mode.baseVersion;
        return p.getString("list_version_" + mode.id, legacy);
    }
    public static int skipped(Context c) { return get(c).getInt("list_skipped_" + profile(c).id, 0); }
    /** Domains currently contributed by the optional extra list URL, 0 when it is off. */
    public static int extraCount(Context c) { return customEnabled(c) ? get(c).getInt("custom_active", 0) : 0; }
    public static String extraUrl(Context c) { return get(c).getString("custom_url", ""); }
    public static boolean customEnabled(Context c) { return get(c).getBoolean("custom_url_enabled", false) && !extraUrl(c).isEmpty(); }
    public static String extraVersion(Context c) { return get(c).getString("custom_version", ""); }

    public static DomainRules loadRules(Context c) throws IOException {
        BlockProfile mode = profile(c);
        DomainRules.ListResult base = loadProfileList(c, mode);
        Set<String> domains = new HashSet<>(base.domains);
        int extra = 0;
        if (customEnabled(c)) {
            Set<String> loaded = loadCustomList(c);
            if (!loaded.isEmpty()) { extra = loaded.size(); domains.addAll(loaded); }
        }
        get(c).edit().putInt("list_count_" + mode.id, domains.size())
                .putInt("list_skipped_" + mode.id, base.skipped)
                .putInt("custom_active", extra).apply();
        try {
            return new DomainRules(domains, DomainRules.parseUser(get(c).getString("allowed", "")),
                    DomainRules.parseUser(get(c).getString("custom", "")));
        } catch (IllegalArgumentException e) {
            throw new IOException("قواعد المستخدم غير صالحة", e);
        }
    }

    private static DomainRules.ListResult loadProfileList(Context c, BlockProfile mode) throws IOException {
        AtomicFile file = new AtomicFile(new File(c.getFilesDir(), mode.asset()));
        try {
            return DomainRules.parseList(file.openRead());
        } catch (IOException e) {
            // A damaged or half-written cache must not lock the user out of protection.
            DomainRules.ListResult bundled = DomainRules.parseList(c.getAssets().open(mode.asset()));
            get(c).edit().putString("list_version_" + mode.id, mode.baseVersion).apply();
            return bundled;
        }
    }

    private static Set<String> loadCustomList(Context c) {
        try {
            return DomainRules.parseList(new AtomicFile(new File(c.getFilesDir(), CUSTOM_FILE)).openRead()).domains;
        } catch (IOException e) {
            return Collections.emptySet();   // keep filtering with the profile list only
        }
    }

    public static Set<String> excluded(Context c) {
        return new HashSet<>(get(c).getStringSet("excluded_apps", Collections.emptySet()));
    }

    /** Rejects anything that is not an absolute https URL, before it is ever stored. */
    public static String validatedUrl(String raw) { return ListSource.validatedUrl(raw); }

    /** Update the explicitly selected profile; a later UI selection cannot redirect this write. */
    public static int updateList(Context c, BlockProfile mode) throws IOException {
        byte[] data = download(c, mode.url(), MAX_LIST_BYTES);
        rejectHtml(data);
        DomainRules.ListResult parsed = DomainRules.parseList(new ByteArrayInputStream(data));
        writeAtomic(c, mode.asset(), data);
        get(c).edit().putInt("list_count_" + mode.id, parsed.domains.size())
                .putInt("list_skipped_" + mode.id, parsed.skipped)
                .putString("list_version_" + mode.id, versionHeader(data, parsed.domains.size())).apply();
        return parsed.domains.size();
    }

    /** Optional extra source. Any failure leaves the previous file and the profile list untouched. */
    public static int updateCustomList(Context c) throws IOException {
        String url = validatedUrl(extraUrl(c));
        if (url.isEmpty()) throw new IOException("أضف رابط قائمة أولًا");
        byte[] data = download(c, url, MAX_LIST_BYTES);
        rejectHtml(data);
        DomainRules.ListResult parsed = DomainRules.parseList(new ByteArrayInputStream(data));
        writeAtomic(c, CUSTOM_FILE, data);
        get(c).edit().putInt("custom_active", parsed.domains.size())
                .putString("custom_version", versionHeader(data, parsed.domains.size()))
                .putInt("custom_skipped", parsed.skipped).apply();
        return parsed.domains.size();
    }

    public static void forgetCustomList(Context c) {
        get(c).edit().putInt("custom_active", 0).putString("custom_version", "").apply();
        AtomicFile file = new AtomicFile(new File(c.getFilesDir(), CUSTOM_FILE));
        try { file.delete(); } catch (Exception ignored) {}
    }

    /** Identifies Safi honestly to the two servers the user explicitly asked us to contact. */
    private static String userAgent(Context c) {
        try {
            String version = c.getPackageManager().getPackageInfo(c.getPackageName(), 0).versionName;
            return "Safi/" + (version == null ? "dev" : version) + " (Android)";
        } catch (PackageManager.NameNotFoundException e) {
            return "Safi/dev (Android)";
        }
    }

    /** Rows a tolerant parse had to ignore in the extra list, for display. */
    public static int extraSkipped(Context c) { return get(c).getInt("custom_skipped", 0); }

    private static void writeAtomic(Context c, String name, byte[] data) throws IOException {
        AtomicFile target = new AtomicFile(new File(c.getFilesDir(), name));
        FileOutputStream stream = null;
        try {
            stream = target.startWrite();
            stream.write(data);
            target.finishWrite(stream);
        } catch (IOException e) {
            if (stream != null) target.failWrite(stream);
            throw e;
        }
    }

    private static String versionHeader(byte[] data, int count) {
        for (String line : new String(data, StandardCharsets.UTF_8).split("\n", 30))
            if (line.startsWith("# Version:")) return line.substring(10).trim();
        return "محدّثة • " + count + " نطاق • " + fingerprint(data);
    }

    /** Short content fingerprint, so the user can tell two "محدّثة" downloads apart. */
    public static String fingerprint(byte[] data) { return ListSource.fingerprint(data); }

    public static String fingerprint(Context c, BlockProfile mode) {
        try {
            byte[] data = readAll(new AtomicFile(new File(c.getFilesDir(), mode.asset())).openRead());
            return fingerprint(data);
        } catch (IOException e) {
            return "—";
        }
    }

    private static byte[] readAll(InputStream in) throws IOException {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) != -1) out.write(buffer, 0, n);
            return out.toByteArray();
        } finally {
            try { in.close(); } catch (IOException ignored) {}
        }
    }

    private static void rejectHtml(byte[] data) throws IOException {
        for (byte b : data) {
            if (b == ' ' || b == '\n' || b == '\r' || b == '\t') continue;
            if (b == '<') throw new IOException("الرابط لا يعرض قائمة نصوص؛ لم يتم تغيير القائمة");
            break;
        }
    }

    /**
     * Explicit, bounded download. Redirects are followed manually and only to https,
     * so a list URL can never downgrade the connection to plaintext.
     */
    private static byte[] download(Context c, String url, int maxBytes) throws IOException {
        String target = url;
        for (int hop = 0; hop < 4; hop++) {
            HttpURLConnection conn = (HttpURLConnection) new URL(target).openConnection();
            try {
                conn.setConnectTimeout(10000);
                conn.setReadTimeout(20000);
                conn.setInstanceFollowRedirects(false);
                conn.setUseCaches(false);
                conn.setRequestProperty("User-Agent", userAgent(c));
                int code = conn.getResponseCode();
                if (code >= 300 && code < 400) {
                    String location = conn.getHeaderField("Location");
                    if (location == null) throw new IOException("إعادة توجيه بدون عنوان؛ لم يتم تغيير القائمة");
                    URI next;
                    try { next = new URI(target).resolve(location); }
                    catch (URISyntaxException e) { throw new IOException("إعادة توجيه غير صالحة", e); }
                    if (!"https".equalsIgnoreCase(next.getScheme()))
                        throw new IOException("إعادة توجيه غير مشفّرة مرفوضة؛ لم يتم تغيير القائمة");
                    target = next.toString();
                    continue;
                }
                if (code != 200) throw new IOException("تعذّر تحميل القائمة (" + code + ")؛ بقيت القائمة الحالية");
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                int total = 0;
                try (InputStream in = conn.getInputStream()) {
                    byte[] buffer = new byte[8192];
                    int n;
                    while ((n = in.read(buffer)) != -1) {
                        total += n;
                        if (total > maxBytes) throw new IOException("حجم قائمة غير متوقع؛ لم يتم تغيير القائمة");
                        out.write(buffer, 0, n);
                    }
                }
                if (out.size() == 0) throw new IOException("قائمة فارغة؛ لم يتم تغيير القائمة");
                return out.toByteArray();
            } finally {
                conn.disconnect();
            }
        }
        throw new IOException("عدد كبير من إعادات التوجيه؛ لم يتم تغيير القائمة");
    }
}
