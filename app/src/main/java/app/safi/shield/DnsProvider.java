/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

/**
 * Closed set of encrypted-DNS upstreams the user may pick between.
 * No remote configuration and no user-supplied URLs: the app can only reach these.
 *
 * Every endpoint below is an IP literal whose certificate is valid for that address, and every
 * provider listed here answered a real wire-format DoH request from this project's own transport
 * in the recorded live test (see TESTING.md). That means no provider needs bootstrap resolution,
 * which is why no hostname endpoint is offered.
 *
 * Deliberately absent: resolvers that only answer over HTTP/2 (Quad9, Mullvad). Android's stack
 * negotiates HTTP/2, but this project's automated live test does not, so they stay out until a
 * real device run proves them.
 */
public enum DnsProvider {
    CLOUDFLARE("cloudflare", "Cloudflare",
            new String[]{"https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query", "https://[2606:4700:4700::1111]/dns-query"},
            "https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/"),
    ADGUARD("adguard", "AdGuard DNS",
            new String[]{"https://94.140.14.14/dns-query", "https://94.140.15.15/dns-query", "https://[2a10:50c0::ad1:ff]/dns-query"},
            "https://adguard.com/en/privacy/dns.html"),
    GOOGLE("google", "Google Public DNS",
            new String[]{"https://8.8.8.8/dns-query", "https://8.8.4.4/dns-query", "https://[2001:4860:4860::8888]/dns-query"},
            "https://developers.google.com/speed/public-dns/privacy");

    public final String id, label;
    private final String[] endpoints;
    public final String privacyUrl;

    DnsProvider(String id, String label, String[] endpoints, String privacyUrl) {
        this.id = id;
        this.label = label;
        this.endpoints = endpoints;
        this.privacyUrl = privacyUrl;
    }

    /** Defensive copy: callers must not be able to rewrite the closed endpoint set. */
    public String[] endpoints() { return endpoints.clone(); }

    public String hosts() {
        StringBuilder out = new StringBuilder();
        for (String endpoint : endpoints) {
            if (out.length() > 0) out.append(" · ");
            out.append(endpoint.replace("https://", "").replace("/dns-query", ""));
        }
        return out.toString();
    }

    /** Unknown or legacy values fall back to the default; never trusts stored text. */
    public static DnsProvider from(String id) {
        if (id != null) for (DnsProvider provider : values()) if (provider.id.equals(id)) return provider;
        return CLOUDFLARE;
    }
}
