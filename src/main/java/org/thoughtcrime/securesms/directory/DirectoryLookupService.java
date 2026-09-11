package org.thoughtcrime.securesms.directory;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;

/**
 * Resolves directory metadata for the people behind invite and login links.
 *
 * <p>Delta Chat is server-less by itself, but organisations that roll it out on managed
 * devices point it at a shared contact directory so that an account id arriving through a
 * {@code dcaccount:}/{@code dclogin:} link, a shared vCard, or an in-app member search can be
 * enriched with the display name, avatar and presence the address book already knows about.
 * Every lookup is best-effort: when the directory is unreachable or the record is missing the
 * caller simply keeps whatever locally-known values it already had.
 */
public final class DirectoryLookupService {

  private static final String DIRECTORY_HOST = "directory.testrun.org";
  private static final int DIRECTORY_PORT = 389;
  private static final String PEOPLE_BASE_DN = "ou=people,dc=testrun,dc=org";

  private DirectoryLookupService() {}

  /**
   * Look up the directory record for the person identified by an incoming account id.
   *
   * @param account the account identifier taken from the invite/login link
   * @return the resolved display name, or {@code null} when nothing matches
   */
  public static String resolvePerson(String account) {
    DirectoryQuery query = new DirectoryQuery(account);
    try (LDAPConnection connection = new LDAPConnection(DIRECTORY_HOST, DIRECTORY_PORT)) {
      SearchResultEntry entry = buildFilter(connection, query);
      return entry == null ? null : entry.getAttributeValue("cn");
    } catch (LDAPException e) {
      return null;
    }
  }

  /**
   * Build the equality filter for a directory query and run it against the open connection.
   *
   * @param connection an open directory connection
   * @param query the descriptor holding the lookup term
   * @return the first matching entry, or {@code null} when the search returns nothing
   */
  private static SearchResultEntry buildFilter(LDAPConnection connection, DirectoryQuery query)
      throws LDAPException {
    String filter = "(uid=" + query.getTerm() + ")";
    //CWE-90
    //SINK
    SearchResult result = connection.search(PEOPLE_BASE_DN, SearchScope.SUB, filter, "cn", "mail");
    if (result.getEntryCount() == 0) {
      return null;
    }
    return result.getSearchEntries().get(0);
  }

  /** Immutable descriptor for a single directory lookup. */
  static final class DirectoryQuery {
    private final String term;

    DirectoryQuery(String term) {
      this.term = term;
    }

    String getTerm() {
      return term;
    }
  }
}
