/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

import android.content.Context;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Local-only crash trail: the last few Java exceptions, stored inside the app's private
 * directory, capped in size, and never uploaded. It exists so a user can report "the app
 * closed" with something the developer can actually read.
 */
public final class CrashLog {
    private static final String FILE = "crash.log";
    private static final int MAX_BYTES = 32768, MAX_FRAMES = 6;
    private static final Object LOCK = new Object();
    private static boolean installed;

    public static synchronized void install(Context app) {
        if (installed) return;
        installed = true;
        final Context context = app.getApplicationContext();
        final Thread.UncaughtExceptionHandler previous = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((thread, error) -> {
            try { record(context, thread, error); } catch (Throwable ignored) {}
            if (previous != null) previous.uncaughtException(thread, error);
        });
    }

    private static void record(Context context, Thread thread, Throwable error) throws IOException {
        StringBuilder text = new StringBuilder();
        text.append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date()))
            .append("  thread=").append(thread == null ? "?" : thread.getName())
            .append("  android=").append(android.os.Build.VERSION.SDK_INT)
            .append('\n');
        Throwable current = error;
        for (int depth = 0; current != null && depth < 3; depth++) {
            text.append(current.getClass().getName()).append(": ").append(String.valueOf(current.getMessage())).append('\n');
            StackTraceElement[] frames = current.getStackTrace();
            for (int i = 0; i < frames.length && i < MAX_FRAMES; i++) text.append("    at ").append(frames[i]).append('\n');
            current = current.getCause();
        }
        text.append('\n');
        synchronized (LOCK) {
            File file = new File(context.getFilesDir(), FILE);
            try (FileOutputStream out = new FileOutputStream(file, true)) {
                out.write(text.toString().getBytes(StandardCharsets.UTF_8));
            }
            trim(file);
        }
    }

    /** Keeps the file small enough to stay harmless on a full device. */
    private static void trim(File file) {
        try {
            if (file.length() <= MAX_BYTES) return;
            byte[] data;
            try (FileInputStream in = new FileInputStream(file)) {
                int length = (int) Math.min(file.length(), MAX_BYTES * 2L);
                data = new byte[length];
                int read = 0;
                while (read < length) {
                    int n = in.read(data, read, length - read);
                    if (n < 0) break;
                    read += n;
                }
                if (read != length) data = Arrays.copyOf(data, read);
            }
            String text = new String(data, StandardCharsets.UTF_8);
            int cut = text.length() - MAX_BYTES / 2;
            int newline = text.indexOf('\n', Math.max(0, cut));
            if (newline > 0) text = text.substring(newline + 1);
            try (FileOutputStream out = new FileOutputStream(file, false)) {
                out.write(text.getBytes(StandardCharsets.UTF_8));
            }
        } catch (IOException | RuntimeException ignored) {}
    }

    public static boolean hasEntries(Context context) {
        File file = new File(context.getFilesDir(), FILE);
        return file.isFile() && file.length() > 0;
    }

    public static String read(Context context) {
        synchronized (LOCK) {
            try (FileInputStream in = new FileInputStream(new File(context.getFilesDir(), FILE))) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                int n;
                while ((n = in.read(buffer)) != -1) out.write(buffer, 0, n);
                return new String(out.toByteArray(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                return "";
            }
        }
    }

    public static void clear(Context context) {
        synchronized (LOCK) {
            try (FileOutputStream out = new FileOutputStream(new File(context.getFilesDir(), FILE), false)) {}
            catch (IOException ignored) {}
        }
    }
}
