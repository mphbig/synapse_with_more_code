import os
import sys
import json
import uuid
import datetime


ALLOWED_AUTHORIZATIONS = ["Ews2Case","CarbonBlack2Alert","LeakWatch2Alert","Rapid7IDRAlerts2Alert","SentinelOne"]
ACCESS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'conf', 'synapse_webhook_access.json')

def add(description, org_name, secret, allow):
    file_content = None
    try:
        with open(ACCESS_FILE, 'r') as f:
            file_content = json.load(f)
    except FileNotFoundError:
        print("Attention : le fichier des accès api synapse est introuvable ! S'il s'agit de la première exécution, ignorez ce message.")
        file_content = {}
    except json.decoder.JSONDecodeError:
        print("Attention : le fichier des accès api synapse est erroné ! Le précédent le contenu du fichier précédent sera perdu !.")
        file_content = {}

    new_uuid = str(uuid.uuid4())
    try:
        url_code = max([file_content[auth]['url_code'] for auth in file_content]) + 1
    except ValueError:
        # happens on first run
        url_code = 1

    allowed = ALLOWED_AUTHORIZATIONS if "*" in allow.split(',') else allow.split(',')

    file_content[new_uuid] = {
        'description': description,
        'url_code': url_code,
        'org_name': org_name,
        'hmac': secret,
        'active': 1,
        'allowed': allowed
    }

    with open(ACCESS_FILE, 'w') as f:
        f.write(json.dumps(file_content, indent=4, ensure_ascii=False))

    print("Nouvelle clé api : {} pour le tenant : {} avec le url_code : {}".format(new_uuid, org_name, url_code))


def delete(api_key):
    file_content = None
    try:
        with open(ACCESS_FILE, 'r') as f:
            file_content = json.load(f)
    except FileNotFoundError:
        print("Attention : le fichier des accès api synapse est introuvable !\nRe-lancez ce script avec l'option 'ajouter' afin de le créer !")
        exit(2)

    for auth in file_content:
        if auth == api_key:
            deleted = file_content.pop(auth)
            print("Accès supprimés !\n{}".format(deleted))
            break

    with open(ACCESS_FILE, 'w') as f:
        f.write(json.dumps(file_content, indent=4))


def activate(api_key):
    file_content = None
    try:
        with open(ACCESS_FILE, 'r') as f:
            file_content = json.load(f)
    except FileNotFoundError:
        print("Attention : le fichier des accès api synapse est introuvable !\nRe-lancez ce script avec l'option 'ajouter' afin de le créer !")
        exit(2)

    for auth in file_content:
        if auth == api_key:
            file_content[auth]['active'] = 1
            print("Accès activé !")
            break

    with open(ACCESS_FILE, 'w') as f:
        f.write(json.dumps(file_content, indent=4))


def deactivate(api_key):
    file_content = None
    try:
        with open(ACCESS_FILE, 'r') as f:
            file_content = json.load(f)
    except FileNotFoundError:
        print("Attention : le fichier des accès api synapse est introuvable !\nRe-lancez ce script avec l'option 'ajouter' afin de le créer !")
        exit(2)

    for auth in file_content:
        if auth == api_key:
            file_content[auth]['active'] = 0
            print("Accès désactivé !")
            break

    with open(ACCESS_FILE, 'w') as f:
        f.write(json.dumps(file_content, indent=4))


def usage():
    print("Usage: python3 synapse_access_generator.py {ajouter|supprimer|activer|desactiver}")
    exit(1)


def is_allowed_rights(rights):
    for right in rights:
        if right not in ALLOWED_AUTHORIZATIONS and not right == "*":
            return False
    return True

if __name__ == '__main__':
    if len(sys.argv) > 1:
        if os.path.exists(ACCESS_FILE):
            os.system("cp -b {} {}".format(ACCESS_FILE, "{}_{}.json".format(ACCESS_FILE.split('.')[0], datetime.datetime.now().strftime("%d%m%Y"))))

        if sys.argv[1] == "ajouter":
            description = input("Description de l'accès >")
            org_name = input("Nom du client, doit être la même valeur que dans TheHive >")
            secret = input("Secret, clé \"secret\" utilisée pour vérification de l'intégrité des données envoyées >")
            while True:
                allow = input("Autorisations, valeurs possibles : {}, exemple: \"Ews2Case,CarbonBlack2Alert\" >".format(ALLOWED_AUTHORIZATIONS))
                if is_allowed_rights(allow.split(',')):
                    break
            add(description, org_name, secret, allow)

        elif sys.argv[1] == "activer":
            api_key = input("Veuillez saisir la clé API que vous souhaitez activer >")
            activate(api_key)

        elif sys.argv[1] == "desactiver":
            api_key = input("Veuillez saisir la clé API que vous souhaitez désactiver >")
            deactivate(api_key)

        elif sys.argv[1] == "supprimer":
            api_key = input("Veuillez saisir la clé API que vous souhaitez supprimer >")
            delete(api_key)

        else:
            usage()

        print("N'oubliez pas de redémarrer synapse pour que les changements prennent effet ! '# supervisorctl restart synapse'")

    else:
        usage()
