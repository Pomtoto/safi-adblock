/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

import java.io.*;
import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Immutable domain/suffix policy. No regexes, URLs, IPs, or network calls.
 *
 * List parsing is deliberately tolerant of the formats people actually subscribe to
 * (plain wildcard lists, hosts files, Adblock-style {@code ||domain^}), while still
 * refusing a list that lost too much of its content: a partially valid download must
 * never silently replace a good one.
 */
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

    /** Result of a tolerant parse: the domains plus how much had to be ignored. */
    public static final class ListResult {
        public final Set<String> domains;
        public final int accepted, skipped, comments;

        ListResult(Set<String> domains, int accepted, int skipped, int comments) {
            this.domains = domains;
            this.accepted = accepted;
            this.skipped = skipped;
            this.comments = comments;
        }

        public String summary() {
            return accepted + " نطاق" + (skipped > 0 ? " • تم تجاهل " + skipped + " سطرًا" : "");
        }
    }

    private static final int MIN_ACCEPTED = 1000;
    private static final int MAX_REJECT_PERCENT = 5;
    private static final int MAX_CHARS = 16 * 1024 * 1024;
    public static final int USER_LIMIT = 5000;

    /** Tolerant parse for downloaded and bundled lists. Throws if the result looks truncated. */
    public static ListResult parseList(InputStream stream) throws IOException {
        Set<String> domains = new HashSet<>(1 << 16);
        int accepted = 0, skipped = 0, comments = 0, chars = 0;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8), 1 << 16)) {
            String line;
            boolean first = true;
            while ((line = reader.readLine()) != null) {
                chars += line.length() + 1;
                if (chars > MAX_CHARS) throw new IOException("القائمة أكبر من الحد المسموح");
                if (first) {
                    first = false;
                    if (!line.isEmpty() && line.charAt(0) == '\uFEFF') line = line.substring(1);
                }
                line = line.trim();
                if (line.isEmpty()) continue;
                char lead = line.charAt(0);
                if (lead == '#' || lead == '!' || lead == '[' || line.startsWith("//")) { comments++; continue; }
                boolean any = false;
                for (String candidate : candidates(line)) {
                    try { domains.add(normalize(candidate)); any = true; }
                    catch (IllegalArgumentException ignored) { /* counted once per line, below */ }
                }
                if (any) accepted++; else skipped++;
            }
        }
        int considered = accepted + skipped;
        if (domains.size() < MIN_ACCEPTED)
            throw new IOException("قائمة حجب ناقصة أو غير صالحة: " + domains.size() + " نطاقًا فقط");
        if (skipped > 0 && skipped * 100 > considered * MAX_REJECT_PERCENT)
            throw new IOException("القائمة تحتوي " + skipped + " سطرًا غير صالح؛ لم يتم استبدال القائمة الحالية");
        return new ListResult(domains, accepted, skipped, comments);
    }

    /** Kept for callers written against 1.1.0. */
    public static Set<String> readList(InputStream stream) throws IOException { return parseList(stream).domains; }

    private static final String WHITESPACE = " \t\u00a0";

    /**
     * Extracts domain candidates from one list line:
     * {@code ads.example.com}, {@code 0.0.0.0 ads.example.com hosts.example.com},
     * {@code ||ads.example.com^}, {@code *.ads.example.com}.
     * Returns an empty array for a line that is valid but not a domain rule.
     */
    private static String[] candidates(String line) {
        int comment = line.indexOf(" #");
        if (comment > 0) line = line.substring(0, comment).trim();
        if (line.isEmpty()) return new String[0];
        int split = -1;
        for (int i = 0; i < line.length(); i++) if (WHITESPACE.indexOf(line.charAt(i)) >= 0) { split = i; break; }
        if (split > 0) {
            String head = line.substring(0, split);
            if (!isHostAddress(head)) return new String[]{head};
            List<String> names = new ArrayList<>(2);
            for (String token : line.substring(split).trim().split("[ \t\u00a0]+"))
                if (!token.isEmpty() && !isHostAddress(token)) names.add(token);
            return names.toArray(new String[0]);
        }
        if (line.startsWith("||")) line = line.substring(2);       // Adblock network rule
        else if (line.startsWith("|") || line.startsWith("@@")) return new String[0];
        if (line.endsWith("^")) line = line.substring(0, line.length() - 1);
        boolean wildcardPrefix = line.startsWith("*.");
        if (line.indexOf('$') >= 0 || (line.indexOf('*') >= 0 && !wildcardPrefix)
                || line.indexOf('/') >= 0 || line.indexOf('=') >= 0 || line.indexOf(',') >= 0)
            return new String[0];                                   // rule modifiers / syntax we do not model
        return new String[]{line};
    }

    private static boolean isHostAddress(String token) {
        if (token.equals("0.0.0.0") || token.equals("127.0.0.1") || token.equals("::1") || token.equals("::")
                || token.equals("0.0.0.0/0") || token.equals("localhost")) return true;
        return false;
    }

    public static String normalize(String raw) {
        String value = raw.trim();
        if (value.startsWith("*.")) value = value.substring(2);
        while (value.endsWith(".")) value = value.substring(0, value.length() - 1);
        if (value.isEmpty() || value.contains(":") || value.contains("/") || value.contains("@"))
            throw new IllegalArgumentException("أدخل نطاقًا فقط، مثل example.com");
        boolean plainAscii = true;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-')) {
                plainAscii = false;
                break;
            }
        }
        if (plainAscii) return validate(value.toLowerCase(Locale.ROOT), raw);
        String idn;
        try { idn = IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT); }
        catch (IllegalArgumentException e) { throw new IllegalArgumentException("اسم نطاق غير صالح: " + raw); }
        return validate(idn, raw);
    }

    private static String validate(String value, String raw) {
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
            if (set.size() > USER_LIMIT) throw new IllegalArgumentException("الحد الأقصى " + USER_LIMIT + " نطاق");
        }
        return set;
    }

    public static String userText(Set<String> domains) { return String.join("\n", new TreeSet<>(domains)); }
}
