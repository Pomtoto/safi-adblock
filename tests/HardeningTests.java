/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import javax.net.ssl.HttpsURLConnection;

/**
 * Deterministic JVM tests for the 1.2.0 hardening work: request coalescing, per-endpoint
 * circuit breakers, the overall lookup time budget, connection-pool behaviour, negative
 * caching (failure and NXDOMAIN), overload signalling and tolerant list parsing.
 * No network access and no Android runtime are required.
 */
public final class HardeningTests {
    static int tests;
    static void check(boolean ok, String label) { tests++; if (!ok) throw new AssertionError(label); }

    /** Minimal provider shape for endpoint scripting; nothing is reachable in a unit test. */
    static final class DnsProviderStub {
        private final String[] endpoints;
        DnsProviderStub(String[] endpoints) { this.endpoints = endpoints; }
        String[] endpoints() { return endpoints; }
    }

    static final class FakeClock {
        long ms;
        long now() { return ms; }
    }

    /** Lets the scripted responder build DNS wire responses, including failures. */
    interface Responder { byte[] apply(byte[] query) throws IOException; }

    /** Scripted HTTPS factory: never touches a socket, and advances a fake clock per attempt. */
    static final class Harness implements DohResolver.ConnectionFactory {
        final FakeClock clock = new FakeClock();
        final Map<String, Integer> attempts = new LinkedHashMap<>();
        final Map<String, Integer> disconnects = new LinkedHashMap<>();
        final Map<String, Integer> failuresLeft = new LinkedHashMap<>();
        final Set<String> dead = new HashSet<>();
        Object provider = DnsProvider.CLOUDFLARE;
        long costMs = 0;
        Responder responder = CoreTests::aResponse;

        public HttpsURLConnection open(URL url) {
            String key = url.toString();
            attempts.merge(key, 1, Integer::sum);
            clock.ms += costMs;
            Integer left = failuresLeft.get(key);
            boolean fail = dead.contains(key) || (left != null && left > 0);
            if (left != null && left > 0) failuresLeft.put(key, left - 1);
            return new Fake(key, this, fail);
        }

        int calls(String host) {
            int total = 0;
            for (Map.Entry<String, Integer> entry : attempts.entrySet())
                if (entry.getKey().contains(host)) total += entry.getValue();
            return total;
        }
        int totalCalls() {
            int total = 0;
            for (int value : attempts.values()) total += value;
            return total;
        }
        void script(String host, int failures) {
            for (String endpoint : endpointsOf(host)) failuresLeft.put(endpoint, failures);
        }
        void kill(String host) { dead.addAll(endpointsOf(host)); }
        List<String> endpointsOf(String host) {
            List<String> found = new ArrayList<>();
            String[] endpoints = provider instanceof DnsProviderStub ? ((DnsProviderStub) provider).endpoints() : ((DnsProvider) provider).endpoints();
            for (String endpoint : endpoints) if (endpoint.contains(host)) found.add(endpoint);
            return found;
        }
    }

    static final class Fake extends HttpsURLConnection {
        private final String key;
        private final Harness harness;
        private final boolean fail;
        private final ByteArrayOutputStream request = new ByteArrayOutputStream();
        Fake(String key, Harness harness, boolean fail) {
            super(null);
            this.key = key;
            this.harness = harness;
            this.fail = fail;
        }
        public void connect() {}
        public void disconnect() { harness.disconnects.merge(key, 1, Integer::sum); }
        public boolean usingProxy() { return false; }
        // Abstract in the desktop JDK (not on Android); TLS never happens in these tests.
        public String getCipherSuite() { return "TLS_NULL"; }
        public java.security.cert.Certificate[] getServerCertificates() { return new java.security.cert.Certificate[0]; }
        public java.security.cert.Certificate[] getLocalCertificates() { return null; }
        public void setRequestMethod(String method) {}
        public void setInstanceFollowRedirects(boolean follow) {}
        public void setUseCaches(boolean useCaches) {}
        public void setDoOutput(boolean doOutput) {}
        public void setRequestProperty(String key, String value) {}
        public void setFixedLengthStreamingMode(int length) {}
        public void setConnectTimeout(int timeout) {}
        public void setReadTimeout(int timeout) {}
        public OutputStream getOutputStream() { return request; }
        public int getResponseCode() throws IOException {
            if (fail) throw new IOException("simulated upstream failure");
            return 200;
        }
        public String getContentType() { return "application/dns-message"; }
        public InputStream getInputStream() throws IOException { return new ByteArrayInputStream(harness.responder.apply(request.toByteArray())); }
    }

    static final class Events implements DohResolver.Events {
        int queries, blocked, errors, ok, failures, coalesced;
        final List<Long> latencies = new ArrayList<>();
        public void request() { queries++; }
        public void blocked() { blocked++; }
        public void error() { errors++; }
        public void upstreamOk() { ok++; }
        public void upstreamFailed(long ms) { failures++; }
        public void coalesced() { coalesced++; }
        public void latency(long ms) { latencies.add(ms); }
    }

    static DomainRules rules(String... blocked) {
        Set<String> set = new HashSet<>(Arrays.asList(blocked));
        return new DomainRules(set, Collections.emptySet(), Collections.emptySet());
    }

    static byte[] soaAnswer(byte[] query, int rcode, long ttl) throws IOException {
        byte[] head = Arrays.copyOfRange(query, 0, 12);
        DnsCodec.put16(head, 2, 0x8180 | (rcode & 15));
        DnsCodec.put16(head, 6, 0);
        DnsCodec.put16(head, 8, 1);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(head, 0, head.length);
        int questionEnd = 12;
        while (query[questionEnd] != 0) questionEnd += (query[questionEnd] & 255) + 1;
        questionEnd += 5;
        out.write(query, 12, questionEnd - 12);
        out.write(new byte[]{(byte) 0xc0, 0x0c});
        DnsCodec.put16(head, 0, 6);
        out.write(new byte[]{0, 6, 0, 1});
        byte[] ttlBytes = new byte[4];
        DnsCodec.put32(ttlBytes, 0, ttl);
        out.write(ttlBytes, 0, 4);
        byte[] rdLength = new byte[2];
        DnsCodec.put16(rdLength, 0, 22);
        out.write(rdLength, 0, 2);
        out.write(0);
        out.write(0);
        out.write(new byte[20]);
        return out.toByteArray();
    }

    static void coalescing() throws Exception {
        Harness harness = new Harness();
        Events events = new Events();
        try (DohResolver resolver = new DohResolver(rules(), new DohResolver.HttpsTransport(DnsProvider.CLOUDFLARE, harness, harness.clock::now), events, harness.clock::now)) {
            int threads = 8;
            ExecutorService pool = Executors.newFixedThreadPool(threads);
            CountDownLatch start = new CountDownLatch(1);
            List<Future<byte[]>> results = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                final int id = 100 + i;
                results.add(pool.submit(() -> { start.await(); return resolver.resolve(DnsCodec.query("example.com", 1, id)); }));
            }
            start.countDown();
            Set<Integer> ids = new TreeSet<>();
            byte[] first = null;
            for (int i = 0; i < threads; i++) {
                byte[] reply = results.get(i).get(20, TimeUnit.SECONDS);
                if (first == null) first = reply;
                else check(first != reply, "each client gets its own array");
                ids.add(DnsCodec.u16(reply, 0));
                check((DnsCodec.u16(reply, 2) & 15) == 0 && DnsCodec.u16(reply, 6) == 1, "coalesced reply is valid");
            }
            pool.shutdown();
            check(ids.size() == threads, "every caller keeps its own query ID");
            check(harness.totalCalls() == 1, "identical in-flight question hits upstream once, got " + harness.totalCalls());
            check(events.coalesced == threads - 1, "coalesced events reported");
            check(events.queries == threads && events.errors == 0, "counters stay honest");

            byte[] other = resolver.resolve(DnsCodec.query("other.example", 1, 7));
            check(harness.totalCalls() == 2, "different names are not merged");
            check(DnsCodec.u16(other, 0) == 7, "second name answered");
        }
    }

    static void breaker() throws Exception {
        // Single-endpoint provider: once the breaker is open the lookup must fail fast
        // instead of paying a connect timeout on every single request.
        Harness single = new Harness();
        String[] onlyEndpoint = {"https://192.0.2.1/dns-query"};   // TEST-NET-1: never routable
        single.provider = new DnsProviderStub(onlyEndpoint);
        single.kill("192.0.2.1");
        Events events = new Events();
        DohResolver.HttpsTransport one = new DohResolver.HttpsTransport(onlyEndpoint, single, single.clock::now);
        try (DohResolver resolver = new DohResolver(rules(), one, events, single.clock::now)) {
            resolver.resolve(DnsCodec.query("a.example", 1, 1));
            resolver.resolve(DnsCodec.query("b.example", 1, 2));
            check(single.totalCalls() == 2, "two failures paid before the breaker opens");
            for (int i = 0; i < 5; i++) resolver.resolve(DnsCodec.query("c" + i + ".example", 1, i + 3));
            check(single.totalCalls() == 2, "open breaker stops paying a timeout per lookup, calls=" + single.totalCalls());
            check(one.openEndpoints() == 1, "dead endpoint reported as open");
            check(events.failures >= 7, "every failed lookup reported to the app");
            check(events.errors >= 7, "failed lookups counted");

            single.clock.ms += DohResolver.HttpsTransport.OPEN_BASE_MS + 1;
            resolver.resolve(DnsCodec.query("probe.example", 1, 99));
            check(single.totalCalls() == 3, "exactly one half-open probe after the backoff");
            check(one.openEndpoints() == 1, "probe failure re-opens with a longer backoff");
            resolver.resolve(DnsCodec.query("probe2.example", 1, 100));
            check(single.totalCalls() == 3, "no extra attempts while the longer backoff is active");

            single.dead.clear();
            single.clock.ms += DohResolver.HttpsTransport.OPEN_MAX_MS + 1;
            byte[] healed = resolver.resolve(DnsCodec.query("heal.example", 1, 101));
            check((DnsCodec.u16(healed, 2) & 15) == 0, "resolution succeeds again after recovery");
            check(one.openEndpoints() == 0, "success closes the breaker");
        }

        // Multi-endpoint provider: a dead primary is skipped while the healthy one answers.
        Harness multi = new Harness();
        multi.kill("1.1.1.1");
        DohResolver.HttpsTransport many = new DohResolver.HttpsTransport(DnsProvider.CLOUDFLARE, multi, multi.clock::now);
        try (DohResolver resolver = new DohResolver(rules(), many, new Events(), multi.clock::now)) {
            resolver.resolve(DnsCodec.query("x.example", 1, 1));
            check(multi.calls("1.1.1.1") == 1, "dead primary paid once");
            resolver.resolve(DnsCodec.query("y.example", 1, 2));
            check(multi.calls("1.1.1.1") == 1, "dead primary is not retried after a healthy success");
            check(multi.totalCalls() == 3, "healthy endpoint carried both lookups, calls=" + multi.totalCalls());
        }
    }

    static DohResolver.Transport transportOf(DohResolver resolver) throws Exception {
        java.lang.reflect.Field field = DohResolver.class.getDeclaredField("transport");
        field.setAccessible(true);
        return (DohResolver.Transport) field.get(resolver);
    }

    static void timeBudget() throws Exception {
        Harness harness = new Harness();
        harness.costMs = 12000;         // every attempt burns more than the whole budget
        for (String endpoint : DnsProvider.CLOUDFLARE.endpoints()) harness.dead.add(endpoint);
        Events events = new Events();
        try (DohResolver resolver = new DohResolver(rules(), new DohResolver.HttpsTransport(DnsProvider.CLOUDFLARE, harness, harness.clock::now), events, harness.clock::now)) {
            byte[] reply = resolver.resolve(DnsCodec.query("slow.example", 1, 5));
            check((DnsCodec.u16(reply, 2) & 15) == 2, "failing resolver returns SERVFAIL");
            check(harness.totalCalls() == 1, "time budget stops the fan-out, attempts=" + harness.totalCalls());
            check(events.failures >= 1, "transport failure reported to the app");
            check(events.errors >= 1, "hard failure counted");

            long after = harness.totalCalls();
            resolver.resolve(DnsCodec.query("slow.example", 1, 6));
            check(harness.totalCalls() == after, "negative cache prevents a second doomed fan-out");

            resolver.resolve(DnsCodec.query("unseen.example", 1, 7));
            check(harness.totalCalls() == after + 1, "a different name still gets one bounded attempt");
        }
    }

    static void pooling() throws Exception {
        Harness harness = new Harness();
        try (DohResolver resolver = new DohResolver(rules(), new DohResolver.HttpsTransport(DnsProvider.CLOUDFLARE, harness, harness.clock::now), new Events(), harness.clock::now)) {
            harness.script("1.1.1.1", 1);
            resolver.resolve(DnsCodec.query("pool.example", 1, 1));
            resolver.resolve(DnsCodec.query("pool2.example", 1, 2));
            int failedDisconnects = 0;
            for (Map.Entry<String, Integer> entry : harness.disconnects.entrySet())
                if (entry.getKey().contains("1.1.1.1")) failedDisconnects += entry.getValue();
            check(failedDisconnects == 1, "failed connection is closed, successful ones stay pooled");
            int totalDisconnects = 0;
            for (int value : harness.disconnects.values()) totalDisconnects += value;
            check(totalDisconnects == 1, "one disconnect for one failure, got " + totalDisconnects);
        }
    }

    static void negativeCaching() throws Exception {
        Harness harness = new Harness();
        for (String endpoint : DnsProvider.CLOUDFLARE.endpoints()) harness.dead.add(endpoint);
        Events events = new Events();
        DohResolver.HttpsTransport transport = new DohResolver.HttpsTransport(DnsProvider.CLOUDFLARE, harness, harness.clock::now);
        try (DohResolver resolver = new DohResolver(rules(), transport, events, harness.clock::now)) {
            long callsAfterFirst;
            try {
                resolver.resolve(DnsCodec.query("dead.example", 1, 1));
            } finally {
                callsAfterFirst = harness.totalCalls();
            }
            check(callsAfterFirst >= 1, "first failure reached the network");
            harness.clock.ms += 5000;
            byte[] second = resolver.resolve(DnsCodec.query("dead.example", 1, 2));
            check((DnsCodec.u16(second, 2) & 15) == 2, "cached failure still returns SERVFAIL");
            check(harness.totalCalls() == callsAfterFirst, "negative cache absorbed the repeat lookup");
            harness.clock.ms += 30000;
            harness.dead.clear();
            byte[] third = resolver.resolve(DnsCodec.query("dead.example", 1, 3));
            check(harness.totalCalls() > callsAfterFirst && (DnsCodec.u16(third, 2) & 15) == 0, "cache expires and the name resolves again");
        }
    }

    static void negativeTtlCache() throws Exception {
        Harness harness = new Harness();
        harness.responder = query -> soaAnswer(query, 3, 300);
        DohResolver.HttpsTransport transport = new DohResolver.HttpsTransport(DnsProvider.CLOUDFLARE, harness, harness.clock::now);
        try (DohResolver resolver = new DohResolver(rules(), transport, new Events(), harness.clock::now)) {
            byte[] first = resolver.resolve(DnsCodec.query("nx.example", 1, 11));
            check((DnsCodec.u16(first, 2) & 15) == 3, "NXDOMAIN passed through");
            byte[] second = resolver.resolve(DnsCodec.query("nx.example", 1, 12));
            check(harness.totalCalls() == 1, "NXDOMAIN is cached, calls=" + harness.totalCalls());
            check(DnsCodec.u16(second, 0) == 12 && (DnsCodec.u16(second, 2) & 15) == 3, "cached NXDOMAIN keeps the caller's ID");
            check(DnsCodec.negativeTtl(soaAnswer(DnsCodec.query("x.example", 1, 0), 3, 600)) == 120, "SOA negative TTL capped");
            check(DnsCodec.negativeTtl(CoreTests.aResponse(DnsCodec.query("x.example", 1, 0))) == 0, "positive answer has no negative TTL");
            check(DnsCodec.negativeTtl(DnsCodec.truncated(DnsCodec.query("x.example", 1, 0))) == 0, "truncated reply is never cached");
        }
    }

    static void overloadSignals() {
        Events events = new Events();
        try (DohResolver resolver = new DohResolver(rules(), new DohResolver.Transport() {
            public byte[] exchange(byte[] query) { return CoreTests.aResponse(query); }
            public void close() {}
        }, events)) {
            byte[] query = DnsCodec.query("busy.example", 1, 77);
            byte[] udp = resolver.overloadedUdp(query);
            check((DnsCodec.u16(udp, 2) & 0x0200) != 0, "UDP overload asks the client to retry over TCP");
            check(DnsCodec.u16(udp, 0) == 77, "overload reply keeps the query ID");
            byte[] tcp = resolver.overloadedTcp(query);
            check((DnsCodec.u16(tcp, 2) & 15) == 2, "TCP overload is an honest SERVFAIL");
            check(events.errors == 2 && events.queries == 2, "overload counted as an error");
        }
    }

    static void providers() {
        check(DnsProvider.values().length >= 3, "several providers offered");
        for (DnsProvider provider : DnsProvider.values()) {
            check(provider.endpoints().length >= 1, provider.id + " has endpoints");
            for (String endpoint : provider.endpoints()) {
                check(endpoint.startsWith("https://"), provider.id + " endpoint is encrypted");
                check(endpoint.endsWith("/dns-query"), provider.id + " endpoint is a DoH path");
            }
            String[] copy = provider.endpoints();
            String original = copy[0];
            copy[0] = "https://evil.example/dns-query";
            check(provider.endpoints()[0].equals(original), provider.id + " endpoint list is defensive");
            check(provider.privacyUrl.startsWith("https://"), provider.id + " privacy link is encrypted");
        }
        check(DnsProvider.from("adguard") == DnsProvider.ADGUARD, "known provider id");
        check(DnsProvider.from("quad9") == DnsProvider.CLOUDFLARE, "unverified provider id is not offered");
        check(DnsProvider.from("../../etc/passwd") == DnsProvider.CLOUDFLARE, "unknown provider falls back");
        check(ListSource.validatedUrl("https://example.com/list.txt").equals("https://example.com/list.txt"), "https url accepted");
        for (String bad : new String[]{"http://example.com/list.txt", "ftp://example.com/x", "https://", "example.com/list.txt", "https://a:b@example.com/list.txt"}) {
            boolean rejected = false;
            try { ListSource.validatedUrl(bad); } catch (IllegalArgumentException expected) { rejected = true; }
            check(rejected, "rejected url " + bad);
        }
        check(ListSource.validatedUrl("").isEmpty(), "empty url clears the setting");
        check(ListSource.fingerprint("abc".getBytes(StandardCharsets.UTF_8)).length() == 12, "content fingerprint is short and stable");
        check(ListSource.fingerprint("abc".getBytes(StandardCharsets.UTF_8)).equals(ListSource.fingerprint("abc".getBytes(StandardCharsets.UTF_8))), "fingerprint is deterministic");
        check(!ListSource.fingerprint("abd".getBytes(StandardCharsets.UTF_8)).equals(ListSource.fingerprint("abc".getBytes(StandardCharsets.UTF_8))), "fingerprint changes with content");
    }

    static String bigList(String extra) {
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < 1200; i++) text.append("blocked").append(i).append(".example\n");
        return text + extra;
    }

    static DomainRules.ListResult parse(String text) throws IOException {
        return DomainRules.parseList(new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)));
    }

    static void listParsing() throws Exception {
        DomainRules.ListResult hosts = parse(bigList("0.0.0.0 ads.example.com\n127.0.0.1 tracker.example.org\n::1 ipv6.example.net\n"));
        check(hosts.domains.contains("ads.example.com") && hosts.domains.contains("tracker.example.org")
                && hosts.domains.contains("ipv6.example.net"), "hosts-file rows are understood");
        check(hosts.domains.contains("blocked7.example"), "plain rows still parsed");

        DomainRules.ListResult adblock = parse(bigList("||ads.example.com^\n! an Adblock comment\n[Adblock Plus 2.0]\nplain.example.com # inline note\n"));
        check(adblock.domains.contains("ads.example.com"), "Adblock rule unwrapped");
        check(adblock.domains.contains("plain.example.com"), "inline comment stripped");
        check(adblock.comments >= 2 && adblock.skipped == 0, "comments are not counted as damage");

        DomainRules.ListResult tolerant = parse(bigList("not a domain at all\ncom\n||ads.example.com^$third-party\n*bad*.example.com\n"));
        check(tolerant.skipped == 4, "unsupported rows are skipped, got " + tolerant.skipped);
        check(tolerant.domains.size() == 1200, "good rows survive a broken line");

        DomainRules.ListResult multi = parse(bigList("0.0.0.0  a.example.com b.example.com\n"));
        check(multi.domains.contains("a.example.com") && multi.domains.contains("b.example.com"), "multi-name hosts row");

        boolean smallRejected = false;
        try { parse("ads.example.com\ntracker.example.com\n"); } catch (IOException expected) { smallRejected = true; }
        check(smallRejected, "a tiny list is refused instead of replacing a good one");

        StringBuilder mostlyBroken = new StringBuilder();
        for (int i = 0; i < 1200; i++) mostlyBroken.append("bad row ").append(i).append('\n');
        boolean rejected = false;
        try { parse(mostlyBroken.toString()); } catch (IOException expected) { rejected = true; }
        check(rejected, "a mostly unparsable download is refused");

        StringBuilder mostlyHtml = new StringBuilder("<!doctype html><html>not a list</html>\n");
        for (int i = 0; i < 40; i++) mostlyHtml.append("bad row\n");
        rejected = false;
        try { parse(mostlyHtml.toString()); } catch (IOException expected) { rejected = true; }
        check(rejected, "an HTML error page is refused");

        StringBuilder userRules = new StringBuilder();
        for (int i = 0; i < DomainRules.USER_LIMIT + 1; i++) userRules.append("d").append(i).append(".example\n");
        boolean userRejected = false;
        try { DomainRules.parseUser(userRules.toString()); } catch (IllegalArgumentException expected) { userRejected = true; }
        check(userRejected, "manual rules stay capped");
    }

    static void bundledList(String path) throws Exception {
        DomainRules.ListResult light = DomainRules.parseList(new FileInputStream(path));
        check(light.domains.size() == BlockProfile.LIGHT.baseCount, "bundled list count unchanged: " + light.domains.size());
        check(light.skipped == 0, "bundled list has no unparsable rows, skipped=" + light.skipped);
        check(light.comments > 0, "bundled list header comments recognised");
        DomainRules rules = new DomainRules(light.domains, Collections.singleton("pagead2.googlesyndication.com"), Collections.emptySet());
        check(rules.blocks("ads.doubleclick.net") || rules.blocks("googleads.g.doubleclick.net"), "known ad host blocked");
        check(!rules.blocks("pagead2.googlesyndication.com"), "allowlist wins over the bundled list");
        check(!rules.blocks("example.com"), "ordinary host allowed");
    }

    /** Optional: proves every advertised provider answers over real TLS using the app's own transport. */
    static void liveProviders() throws Exception {
        for (DnsProvider provider : DnsProvider.values()) {
            byte[] query = DnsCodec.query("example.com", 1, 4242);
            try (DohResolver.HttpsTransport transport = new DohResolver.HttpsTransport(provider)) {
                long started = System.nanoTime();
                byte[] reply = transport.exchange(query);
                long elapsed = (System.nanoTime() - started) / 1000000;
                check(DnsCodec.u16(reply, 6) > 0, provider.label + " returned answers");
                check(DnsCodec.u16(reply, 0) == 4242, provider.label + " kept the query ID");
                System.out.println("LIVE " + provider.id + ": " + elapsed + " ms, " + reply.length + " bytes, validation passed");
            }
        }
    }

    public static void main(String[] args) throws Exception {
        coalescing();
        breaker();
        timeBudget();
        pooling();
        negativeCaching();
        negativeTtlCache();
        overloadSignals();
        providers();
        listParsing();
        bundledList(args.length > 0 ? args[0] : "../app/src/main/assets/hagezi-light.txt");
        if (Arrays.asList(args).contains("--live")) liveProviders();
        System.out.println("PASS: " + tests + " hardening assertions (coalescing, breaker, budget, pooling, negative cache, list formats)");
    }
}
