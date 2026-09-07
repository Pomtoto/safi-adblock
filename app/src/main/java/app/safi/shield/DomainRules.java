/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

import java.io.*;
import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Immutable domain/suffix policy. No regexes, URLs, IPs, or network calls. */
public final class DomainRules {
    private final Set<String> bundled, allowed, custom;
    public DomainRules(Set<String> bundled, Set<String> allowed, Set<String> custom) {
        this.bundled = Collections.unmodifiableSet(new HashSet<>(bundled));
        this.allowed = Collections.unmodifiableSet(new HashSet<>(allowed));
        this.custom = Collections.unmodifiableSet(new HashSet<>(custom));
    }
    public int count() { return bundled.size(); }
    public boolean isAllowed(String host) { return suffixMatch(allowed, host); }
    public boolean blocks(String host) {
        if (isAllowed(host)) return false;
        return suffixMatch(custom, host) || suffixMatch(bundled, host);
    }
    private static boolean suffixMatch(Set<String> set, String host) {
        String s = host.toLowerCase(Locale.ROOT);
        while (s.endsWith(".")) s = s.substring(0, s.length() - 1);
        while (!s.isEmpty()) {
            if (set.contains(s)) return true;
            int dot = s.indexOf('.');
            if (dot < 0) break;
            s = s.substring(dot + 1);
        }
        return false;
    }
    public static String normalize(String raw) {
        String value = raw.trim();
        if (value.startsWith("*.")) value = value.substring(2);
        if (value.endsWith(".")) value = value.substring(0, value.length() - 1);
        if (value.isEmpty() || value.contains(":") || value.contains("/") || value.contains("@"))
            throw new IllegalArgumentException("أدخل نطاقًا فقط، مثل example.com");
        try { value = IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT); }
        catch (IllegalArgumentException e) { throw new IllegalArgumentException("اسم نطاق غير صالح: " + raw); }
        if (value.length() > 253 || !value.contains(".") || value.matches("[0-9.]+"))
            throw new IllegalArgumentException("اسم نطاق غير صالح: " + raw);
        for (String label : value.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63 || label.startsWith("-") || label.endsWith("-"))
                throw new IllegalArgumentException("اسم نطاق غير صالح: " + raw);
        }
        return value;
    }
    public static Set<String> parseUser(String text) {
        Set<String> set = new TreeSet<>();
        for (String line : text.split("[\\r\\n]+")) {
            if (line.trim().isEmpty()) continue;
            set.add(normalize(line));
            if (set.size() > 1000) throw new IllegalArgumentException("الحد الأقصى ١٠٠٠ نطاق");
        }
        return set;
    }
    public static String userText(Set<String> domains) { return String.join("\n", new TreeSet<>(domains)); }
    public static Set<String> readList(InputStream stream) throws IOException {
        Set<String> result = new HashSet<>(50000);
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line; int chars = 0;
            while ((line = reader.readLine()) != null) {
                chars += line.length() + 1;
                if (chars > 6 * 1024 * 1024) throw new IOException("القائمة أكبر من الحد المسموح");
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                try { result.add(normalize(line)); }
                catch (IllegalArgumentException e) { throw new IOException("صيغة قائمة الحجب غير صالحة", e); }
            }
        }
        if (result.size() < 1000) throw new IOException("قائمة حجب ناقصة؛ لم يتم استبدال القائمة الحالية");
        return result;
    }
}
