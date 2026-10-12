/* SPDX-License-Identifier: GPL-3.0-only */
package app.safi.shield;

import android.annotation.SuppressLint;
import android.app.PendingIntent;
import android.content.*;
import android.graphics.drawable.Icon;
import android.net.VpnService;
import android.os.Build;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

/** Quick Settings tile: start or stop protection without opening the app. */
public final class SafiTileService extends TileService {
    /** The UI asks the tile to re-read state instead of the tile polling in the background. */
    public static void requestRefresh(Context context) {
        try { requestListeningState(context, new ComponentName(context, SafiTileService.class)); }
        catch (RuntimeException ignored) {}
    }

    @Override public void onStartListening() {
        super.onStartListening();
        AppState.init(this);
        publish();
    }

    @Override public void onClick() {
        super.onClick();
        AppState.init(this);
        if (AppState.busy()) { publish(); return; }
        if (AppState.state == AppState.ON) {
            // stopService runs the same teardown path as the in-app button, including cleanup.
            stopService(new Intent(this, ShieldVpnService.class));
            publish();
            return;
        }
        Intent consent = VpnService.prepare(this);
        if (consent != null) { collapseToConsent(consent); return; }
        try { startForegroundService(new Intent(this, ShieldVpnService.class).setAction(ShieldVpnService.START)); }
        catch (RuntimeException ignored) {}
        publish();
    }

    @SuppressLint("StartActivityAndCollapseDeprecated")
    private void collapseToConsent(Intent consent) {
        PendingIntent pending = PendingIntent.getActivity(this, 7, consent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        try {
            // The PendingIntent overload exists from API 34 and throws on older platforms,
            // so the deprecated Intent overload is the only option below that.
            if (Build.VERSION.SDK_INT >= 34) startActivityAndCollapse(pending);
            else startActivityAndCollapse(consent);
        } catch (RuntimeException ignored) {}
    }

    private void publish() {
        Tile tile = getQsTile();
        if (tile == null) return;
        tile.setLabel(getString(R.string.app_name));
        tile.setIcon(Icon.createWithResource(this, R.drawable.ic_shield));
        int state = AppState.state;
        String subtitle;
        if (state == AppState.ON) {
            tile.setState(Tile.STATE_ACTIVE);
            subtitle = "الحماية تعمل";
        } else if (state == AppState.STARTING || state == AppState.STOPPING) {
            tile.setState(Tile.STATE_UNAVAILABLE);
            subtitle = "جارٍ التجهيز…";
        } else {
            tile.setState(Tile.STATE_INACTIVE);
            subtitle = state == AppState.ERROR ? "تحتاج إعادة محاولة" : "متوقفة";
        }
        // setSubtitle arrived in API 29; older tiles simply show the label and state.
        if (Build.VERSION.SDK_INT >= 29) tile.setSubtitle(subtitle);
        tile.updateTile();
    }
}
