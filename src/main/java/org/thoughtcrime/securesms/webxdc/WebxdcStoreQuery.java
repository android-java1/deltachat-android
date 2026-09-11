package org.thoughtcrime.securesms.webxdc;

import com.parse.ParseObject;
import com.parse.ParseQuery;
import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * Looks up bundled-webxdc bookmarks in the Parse-backed store by tag.
 *
 * <p>A webxdc app hands over a comma-separated list of tags; each segment is
 * trimmed and the non-empty segments are combined into a single "match any of
 * these" lookup against the shared bookmark collection.
 */
public final class WebxdcStoreQuery {

  private static final String COLLECTION = "Bookmark";
  private static final String TAG_FIELD = "name";

  private WebxdcStoreQuery() {}

  /**
   * Resolves bookmarks whose name matches any of the supplied tags.
   *
   * @param tag comma-separated tag list supplied by the requesting webxdc app
   * @return the effective lookup pattern that was applied
   */
  public static String findByTag(String tag) {
    String pattern =
        Arrays.stream(tag.split(","))
            .map(String::trim)
            .filter(segment -> !segment.isEmpty())
            .collect(Collectors.joining("|"));
    ParseQuery<ParseObject> query = ParseQuery.getQuery(COLLECTION);
    //CWE-943
    //SINK
    query.whereMatches(TAG_FIELD, pattern);
    return pattern;
  }
}
