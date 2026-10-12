/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

import java.io.*;
import java.net.*;
import javax.net.ssl.HttpsURLConnection;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/**
 * DNS-only encrypted upstream.
 *
 * Hardening over the first release:
 *  - identical in-flight questions are coalesced into one upstream request;
 *  - every endpoint has a circuit breaker, so a blocked or down provider degrades fast
 *    instead of costing a full timeout on each lookup;
 *  - the whole lookup runs inside one time budget and the per-attempt timeouts are clamped
 *    to it, so a single DNS answer can never block a client for many seconds;
 *  - transport failures are negatively cached briefly, so one outage cannot amplify into
 *    a burst of doomed HTTPS requests;
 *  - successful responses keep their pooled connection (no forced disconnect), which removes
 *    a TLS handshake from the hot path;
 *  - negative answers (NXDOMAIN / NODATA with SOA) are cached with the SOA TTL.
 * Default platform certificate and hostname verification stays on.
 */
public final class DohResolver implements AutoCloseable {
    public interface Transport extends AutoCloseable {
        /** Returns a validated reply whose ID is already the (zeroed) query ID. Callers must not mutate it. */
        byte[] exchange(byte[] query) throws IOException;
        void close();
    }
    public interface Events {
        void request();
        void blocked();
        void error();
        void upstreamOk();
        /** Upstream attempt(s) failed after the breaker/budget ran out. */
        default void upstreamFailed(long elapsedMs) {}
        /** Successful upstream round trip, including any coalescing wait. */
        default void latency(long elapsedMs) {}
        /** Served without a new upstream request because an identical one was in flight. */
        default void coalesced() {}
        default long diagnosticTicket() { return 0; }
        default void diagnostic(long ticket, String host, int status) {}
    }
    public interface ConnectionFactory { HttpsURLConnection open(URL url) throws IOException; }
    /** Monotonic millisecond clock, injectable so breaker/budget behaviour is testable. */
    public interface Clock { long nowMs(); }

    /** HTTPS transport with per-endpoint circuit breakers and a single overall time budget. */
    public static final class HttpsTransport implements Transport {
        static final int CONNECT_MS = 1500, READ_MS = 2500, MIN_MS = 400;
        static final long TOTAL_BUDGET_MS = 7000;
        static final long OPEN_BASE_MS = 15000, OPEN_MAX_MS = 120000;
        static final int FAILURES_TO_OPEN = 2;

        private static final class Endpoint {
            final AtomicInteger failures = new AtomicInteger();
            volatile long openUntil;
        }
        private static final class Attempt {
            final URL url; HttpsURLConnection connection;
            Attempt(URL url) { this.url = url; }
        }

        private final ConnectionFactory factory;
        private final String[] endpoints;
        private final Clock clock;
        private final Endpoint[] states;
        private final AtomicInteger preferred = new AtomicInteger();
        private final Set<Attempt> active = ConcurrentHashMap.newKeySet();
        private volatile boolean closed;

        public HttpsTransport(DnsProvider provider) {
            this(provider, url -> (HttpsURLConnection) url.openConnection(), () -> System.nanoTime() / 1000000L);
        }
        public HttpsTransport(ConnectionFactory factory) {
            this(DnsProvider.CLOUDFLARE, factory, () -> System.nanoTime() / 1000000L);
        }
        public HttpsTransport() {
            this(DnsProvider.CLOUDFLARE, url -> (HttpsURLConnection) url.openConnection(), () -> System.nanoTime() / 1000000L);
        }
        public HttpsTransport(DnsProvider provider, ConnectionFactory factory, Clock clock) {
            this(provider.endpoints(), factory, clock);
        }
        public HttpsTransport(String[] endpoints, ConnectionFactory factory, Clock clock) {
            this.factory = factory;
            this.endpoints = endpoints.clone();
            this.clock = clock;
            this.states = new Endpoint[this.endpoints.length];
            for (int i = 0; i < states.length; i++) states[i] = new Endpoint();
        }

        public int endpointCount() { return endpoints.length; }
        /** Visible for tests and for the in-app DNS status line. */
        public int openEndpoints() {
            long now = clock.nowMs();
            int open = 0;
            for (Endpoint endpoint : states) if (endpoint.openUntil > now) open++;
            return open;
        }

        /** Endpoints are tried in preference order; open-breaker endpoints are skipped entirely. */
        private List<Integer> order(long now) {
            List<Integer> order = new ArrayList<>();
            int first = preferred.get();
            for (int i = 0; i < endpoints.length; i++) {
                int index = (first + i) % endpoints.length;
                if (states[index].openUntil <= now) order.add(index);
            }
            // An empty order means every endpoint is in backoff: the lookup fails immediately
            // instead of paying a connect timeout on each of them. The first attempt after the
            // backoff window is the half-open probe, and a success closes the breaker.
            return order;
        }

        private void succeeded(int index) {
            Endpoint endpoint = states[index];
            endpoint.failures.set(0);
            endpoint.openUntil = 0;
            preferred.set(index);
        }

        private void failed(int index) {
            Endpoint endpoint = states[index];
            int failures = endpoint.failures.incrementAndGet();
            if (failures < FAILURES_TO_OPEN) return;
            long backoff = Math.min(OPEN_MAX_MS, OPEN_BASE_MS << Math.min(4, failures - FAILURES_TO_OPEN));
            endpoint.openUntil = clock.nowMs() + backoff;
        }

        public byte[] exchange(byte[] query) throws IOException {
            if (closed) throw new IOException("Resolver stopped");
            long deadline = clock.nowMs() + TOTAL_BUDGET_MS;
            IOException error = null;
            for (int index : order(clock.nowMs())) {
                long remaining = deadline - clock.nowMs();
                if (remaining < MIN_MS) break;
                if (closed) throw new IOException("Resolver stopped");
                try {
                    return attempt(index, query, remaining);
                } catch (IOException e) {
                    error = e;
                    failed(index);
                }
            }
            throw error != null ? error : new IOException("DNS unavailable");
        }

        private byte[] attempt(int index, byte[] query, long budget) throws IOException {
            Attempt attempt = new Attempt(new URL(endpoints[index]));
            boolean ok = false;
            active.add(attempt);
            try {
                HttpsURLConnection conn = factory.open(attempt.url);
                attempt.connection = conn;
                if (closed) throw new IOException("Resolver stopped");
                conn.setConnectTimeout((int) Math.max(MIN_MS, Math.min(CONNECT_MS, budget)));
                conn.setReadTimeout((int) Math.max(MIN_MS, Math.min(READ_MS, budget)));
                conn.setRequestMethod("POST");
                conn.setInstanceFollowRedirects(false);
                conn.setUseCaches(false);
                conn.setDoOutput(true);
                conn.setRequestProperty("Accept", "application/dns-message");
                conn.setRequestProperty("Content-Type", "application/dns-message");
                conn.setFixedLengthStreamingMode(query.length);
                try (OutputStream out = conn.getOutputStream()) { out.write(query); }
                if (conn.getResponseCode() != 200) throw new IOException("DNS HTTPS status: " + conn.getResponseCode());
                String type = conn.getContentType();
                if (type == null || !type.toLowerCase(Locale.ROOT).startsWith("application/dns-message"))
                    throw new IOException("Invalid DNS content type");
                ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                try (InputStream in = conn.getInputStream()) {
                    byte[] buffer = new byte[2048];
                    int n;
                    while ((n = in.read(buffer)) != -1) {
                        if (bytes.size() + n > 65535) throw new IOException("Oversized DNS reply");
                        bytes.write(buffer, 0, n);
                    }
                }
                byte[] answer = bytes.toByteArray();
                DnsCodec.validateResponse(query, answer);
                ok = true;
                succeeded(index);
                return answer;
            } finally {
                active.remove(attempt);
                // A failed socket is never reusable; a successful one is left to the connection
                // pool on purpose, so the next lookup skips the TLS handshake.
                if (!ok && attempt.connection != null) attempt.connection.disconnect();
            }
        }

        public void close() {
            closed = true;
            for (Attempt attempt : active) if (attempt.connection != null) attempt.connection.disconnect();
            active.clear();
        }
    }

    private static final int CACHE_MAX = 256, NEGATIVE_MAX = 256, IN_FLIGHT_MAX = 512;
    private static final long NEGATIVE_TTL_MS = 20000, COALESCE_WAIT_MS = 9000;

    private final DomainRules rules;
    private final Transport transport;
    private final Events events;
    private final Clock clock;
    private final Map<String, CacheEntry> cache = new LinkedHashMap<String, CacheEntry>(64, 0.75f, true) {
        protected boolean removeEldestEntry(Map.Entry<String, CacheEntry> entry) { return size() > CACHE_MAX; }
    };
    private final Map<String, Long> negative = new LinkedHashMap<String, Long>(32, 0.75f, true) {
        protected boolean removeEldestEntry(Map.Entry<String, Long> entry) { return size() > NEGATIVE_MAX; }
    };
    private final ConcurrentHashMap<String, CompletableFuture<byte[]>> inFlight = new ConcurrentHashMap<>();

    private static final class CacheEntry {
        final byte[] value; final long born, ttl;
        CacheEntry(byte[] value, long ttl) { this.value = value.clone(); born = System.nanoTime(); this.ttl = ttl; }
    }

    public DohResolver(DomainRules rules, Transport transport, Events events) {
        this(rules, transport, events, () -> System.nanoTime() / 1000000L);
    }
    public DohResolver(DomainRules rules, Transport transport, Events events, Clock clock) {
        this.rules = rules;
        this.transport = transport;
        this.events = events;
        this.clock = clock;
    }

    private void trace(long ticket, String host, int status) {
        if (ticket != 0) try { events.diagnostic(ticket, host, status); } catch (RuntimeException ignored) {}
    }

    private static String keyOf(byte[] normalized) {
        return Base64.getEncoder().encodeToString(normalized);
    }

    /** Identical questions share one upstream request. The returned array must not be mutated. */
    private byte[] coalesce(String key, byte[] normalized) throws IOException {
        if (inFlight.size() >= IN_FLIGHT_MAX) return transport.exchange(normalized);
        CompletableFuture<byte[]> mine = new CompletableFuture<>();
        CompletableFuture<byte[]> leader = inFlight.putIfAbsent(key, mine);
        if (leader != null) {
            try {
                byte[] shared = leader.get(COALESCE_WAIT_MS, TimeUnit.MILLISECONDS);
                events.coalesced();
                return shared;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while waiting for an identical query", e);
            } catch (ExecutionException e) {
                Throwable cause = e.getCause();
                throw cause instanceof IOException ? (IOException) cause : new IOException("Upstream query failed", cause);
            } catch (TimeoutException e) {
                throw new IOException("Identical query did not finish in time", e);
            }
        }
        try {
            byte[] reply = transport.exchange(normalized);
            mine.complete(reply);
            return reply;
        } catch (IOException e) {
            mine.completeExceptionally(e);
            throw e;
        } finally {
            inFlight.remove(key, mine);
        }
    }

    /**
     * Overload reply for a UDP client: a truncated answer makes the client retry over TCP
     * instead of reporting a hard DNS failure to the user.
     */
    public byte[] overloadedUdp(byte[] query) {
        events.request();
        events.error();
        traceFailure(query);
        return DnsCodec.truncated(query);
    }

    /** Overload reply for a TCP client: honest SERVFAIL, because TCP already is the fallback path. */
    public byte[] overloadedTcp(byte[] query) {
        events.request();
        events.error();
        traceFailure(query);
        return DnsCodec.failure(query);
    }

    /** Kept for callers written against 1.1.0; the UDP behaviour is the safe default. */
    public byte[] overloaded(byte[] query) { return overloadedUdp(query); }

    private void traceFailure(byte[] query) {
        long ticket = events.diagnosticTicket();
        if (ticket == 0) return;
        try { trace(ticket, DnsCodec.question(query).host, DiagnosticRecorder.FAILED); } catch (IOException ignored) {}
    }

    public byte[] resolve(byte[] query) {
        events.request();
        long ticket = events.diagnosticTicket();
        long started = clock.nowMs();
        DnsCodec.Question question = null;
        try {
            question = DnsCodec.question(query);
            if (question.qclass != 1) {
                trace(ticket, question.host, DiagnosticRecorder.FAILED);
                return DnsCodec.unsupported(query);
            }
            if (rules.blocks(question.host)) {
                events.blocked();
                trace(ticket, question.host, DiagnosticRecorder.BLOCKED);
                return DnsCodec.blocked(query);
            }
            byte[] normalized = query.clone();
            DnsCodec.put16(normalized, 0, 0);
            String key = keyOf(normalized);
            int queryId = DnsCodec.u16(query, 0);

            CacheEntry hit;
            synchronized (cache) { hit = cache.get(key); }
            if (hit != null) {
                long elapsed = (System.nanoTime() - hit.born) / 1000000000L;
                if (elapsed < hit.ttl) {
                    trace(ticket, question.host, DiagnosticRecorder.CACHED);
                    return DnsCodec.aged(hit.value, elapsed, queryId);
                }
                synchronized (cache) { cache.remove(key); }
            }

            Long retryAfter;
            synchronized (negative) { retryAfter = negative.get(key); }
            if (retryAfter != null) {
                if (clock.nowMs() < retryAfter) {
                    events.error();
                    trace(ticket, question.host, DiagnosticRecorder.FAILED);
                    return DnsCodec.failure(query);
                }
                synchronized (negative) { negative.remove(key); }
            }

            byte[] wire;
            try {
                wire = coalesce(key, normalized);
            } catch (IOException e) {
                synchronized (negative) { negative.put(key, clock.nowMs() + NEGATIVE_TTL_MS); }
                throw e;
            }
            long elapsed = clock.nowMs() - started;
            events.upstreamOk();
            events.latency(elapsed);

            if (!rules.isAllowed(question.host)) {
                for (String alias : DnsCodec.aliases(wire)) {
                    if (rules.blocks(alias)) {
                        events.blocked();
                        trace(ticket, question.host, DiagnosticRecorder.BLOCKED);
                        return DnsCodec.blocked(query);
                    }
                }
            }
            long ttl = DnsCodec.cacheTtl(wire);
            if (ttl <= 0) ttl = DnsCodec.negativeTtl(wire);
            if (ttl > 0 && wire.length <= 8192) synchronized (cache) { cache.put(key, new CacheEntry(wire, ttl)); }
            trace(ticket, question.host, DiagnosticRecorder.ALLOWED);
            byte[] reply = wire.clone();
            DnsCodec.put16(reply, 0, queryId);
            return reply;
        } catch (IOException | RuntimeException e) {
            events.error();
            events.upstreamFailed(clock.nowMs() - started);
            if (question != null) trace(ticket, question.host, DiagnosticRecorder.FAILED);
            return DnsCodec.failure(query);
        }
    }

    /** Non-zero only when every endpoint is currently in backoff. */
    public int openEndpoints() {
        return transport instanceof HttpsTransport ? ((HttpsTransport) transport).openEndpoints() : 0;
    }

    public int cachedEntries() { synchronized (cache) { return cache.size(); } }

    public void close() {
        transport.close();
        synchronized (cache) { cache.clear(); }
        synchronized (negative) { negative.clear(); }
        inFlight.clear();
    }
}
