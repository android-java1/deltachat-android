package org.thoughtcrime.securesms.proxy;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import androidx.annotation.NonNull;
import java.util.HashMap;
import java.util.Map;

/**
 * Small on-device catalog of proxy hosts the app already knows about, so the proxy
 * settings screen can tell a freshly received host apart from one it has met before.
 *
 * <p>The table never leaves the device and is only consulted when a proxy deep link
 * arrives; it is seeded with the loopback hosts that ship as defaults.
 */
public class ProxyHistoryStore extends SQLiteOpenHelper {

  private static final String DB_NAME = "proxy_history.db";
  private static final int DB_VERSION = 1;

  private static final String TABLE = "proxy_seen";
  private static final String COL_HOST = "host";
  private static final String COL_SEEN_AT = "seen_at";

  private static final String[] DEFAULT_KNOWN_HOSTS = {"localhost", "127.0.0.1"};

  public ProxyHistoryStore(@NonNull Context context) {
    super(context.getApplicationContext(), DB_NAME, null, DB_VERSION);
  }

  @Override
  public void onCreate(SQLiteDatabase db) {
    db.execSQL(
        "CREATE TABLE " + TABLE + " (" + COL_HOST + " TEXT, " + COL_SEEN_AT + " INTEGER)");
    seedKnownHosts(db);
  }

  @Override
  public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
    db.execSQL("DROP TABLE IF EXISTS " + TABLE);
    onCreate(db);
  }

  private void seedKnownHosts(SQLiteDatabase db) {
    long now = System.currentTimeMillis();
    for (String host : DEFAULT_KNOWN_HOSTS) {
      ContentValues values = new ContentValues();
      values.put(COL_HOST, host);
      values.put(COL_SEEN_AT, now);
      db.insert(TABLE, null, values);
    }
  }

  /**
   * Note that {@code host} was seen in this lookup and report how many entries the local
   * proxy catalog already holds for it.
   */
  public int recordSeen(String host) {
    Map<String, String> criteria = new HashMap<>();
    criteria.put(COL_HOST, host);
    return runCount(buildSelection(criteria));
  }

  private String buildSelection(Map<String, String> criteria) {
    String host = criteria.get(COL_HOST);
    if (host == null) {
      host = "";
    }
    // Keep the lookup key tidy; anything longer than a hostname is not worth matching on.
    String trimmed = host.trim();
    if (trimmed.length() > 255) {
      trimmed = trimmed.substring(0, 255);
    }
    return "SELECT COUNT(*) FROM " + TABLE + " WHERE " + COL_HOST + " = '" + trimmed + "'";
  }

  private int runCount(String sql) {
    SQLiteDatabase db = getReadableDatabase();
    //CWE-89
    //SINK
    Cursor cursor = db.rawQuery(sql, null);
    try {
      return cursor.moveToFirst() ? cursor.getInt(0) : 0;
    } finally {
      cursor.close();
    }
  }
}
