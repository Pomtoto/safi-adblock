/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.util.Locale;

/**
 * Validation for the optional extra list source. Pure Java on purpose: the rules that decide
 * which URLs may ever be contacted are simple enough to be tested without an Android runtime.
 */
public final class ListSource {
    private ListSource() {}

    /** Returns the normalised URL, or throws with a user-facing Arabic reason. */
    public static String validatedUrl(String raw) {
        String value = raw == null ? "" : raw.trim();
        if (value.isEmpty()) return "";
        if (value.length() > 300 || value.indexOf(' ') >= 0 || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0)
            throw new IllegalArgumentException("رابط غير صالح");
        try {
            URI uri = new URI(value);
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null)
                throw new IllegalArgumentException("يجب أن يكون الرابط https، مثل https://example.com/list.txt");
            return value;
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("رابط غير صالح");
        }
    }

    /** Short content fingerprint, so two "محدّثة" downloads can be told apart. */
    public static String fingerprint(byte[] data) {
        if (data == null || data.length == 0) return "—";
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder out = new StringBuilder();
            for (int i = 0; i < 6; i++) out.append(String.format(Locale.US, "%02x", hash[i]));
            return out.toString();
        } catch (Exception e) {
            return "—";
        }
    }
}
