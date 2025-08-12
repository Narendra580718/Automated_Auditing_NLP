import argparse
import getpass
import spacy
from ldap3 import Server, Connection, ALL, NTLM
from tabulate import tabulate
from colorama import Fore, Style, init

init(autoreset=True)

def connect_to_ad(server_address, username, password, domain):
    server = Server(server_address, get_info=ALL)
    user = f'{domain}\\{username}'
    conn = Connection(server, user=user, password=password, authentication=NTLM, auto_bind=True)
    return conn

def get_all_users(conn, base_dn):
    conn.search(base_dn, '(objectClass=user)', attributes=['sAMAccountName', 'userAccountControl', 'pwdLastSet', 'lastLogon', 'memberOf', 'userPrincipalName', 'servicePrincipalName'])
    return conn.entries

def check_password_never_expires(user):
    # userAccountControl flag 0x10000 (65536) means password never expires
    uac = int(user.userAccountControl.value)
    return bool(uac & 0x10000)

def check_disabled_account(user):
    # userAccountControl flag 0x2 (2) means account disabled
    uac = int(user.userAccountControl.value)
    return bool(uac & 0x2)

def check_spn_set(user):
    return bool(user.servicePrincipalName.value)

def interpret_command(command):
    nlp = spacy.load('en_core_web_sm')
    doc = nlp(command.lower())
    # Simple intent extraction
    if 'all' in command and ('scan' in command or 'check' in command):
        return {'action': 'scan_all'}
    for token in doc:
        if token.text in ['user', 'account']:
            # Look for username after 'user' or 'account'
            for ent in doc.ents:
                if ent.label_ in ['PERSON', 'ORG'] or ent.text.isalnum():
                    return {'action': 'scan_user', 'username': ent.text}
            # Fallback: look for word after 'user'
            idx = [i for i, t in enumerate(doc) if t.text == token.text]
            if idx and idx[0] + 1 < len(doc):
                return {'action': 'scan_user', 'username': doc[idx[0] + 1].text}
    # Default: scan all
    return {'action': 'scan_all'}


def main():
    parser = argparse.ArgumentParser(description='AD Security Misconfiguration Auditor')
    parser.add_argument('--server', required=True, help='AD server address')
    parser.add_argument('--username', help='Username')
    parser.add_argument('--password', help='Password')
    parser.add_argument('--domain', required=True, help='Domain')
    parser.add_argument('--base-dn', required=True, help='Base DN (e.g., DC=example,DC=com)')
    args = parser.parse_args()

    # Prompt for username and password if not provided
    if not args.username:
        args.username = input('Enter your AD username: ')
    if not args.password:
        args.password = getpass.getpass('Enter your AD password: ')

    # NLP: Ask user for a natural language command
    print('\nYou can type commands like:')
    print('  - Scan all users')
    print('  - Check user jdoe')
    print('  - Find accounts with password never expires')
    user_command = input('Enter your command: ')
    intent = interpret_command(user_command)

    print(f"{Fore.CYAN}[*] Connecting to AD server...")
    conn = connect_to_ad(args.server, args.username, args.password, args.domain)
    print(f"{Fore.GREEN}[+] Connected!")

    if intent['action'] == 'scan_all':
        print(f"{Fore.GREEN}[*] Enumerating all users...")
        users = get_all_users(conn, args.base_dn)
    elif intent['action'] == 'scan_user':
        specific_user = intent['username']
        print(f"{Fore.GREEN}[*] Searching for user: {specific_user}")
        search_filter = f'(sAMAccountName={specific_user})'
        conn.search(args.base_dn, search_filter, attributes=['sAMAccountName', 'userAccountControl', 'pwdLastSet', 'lastLogon', 'memberOf', 'userPrincipalName', 'servicePrincipalName'])
        users = conn.entries
    else:
        print(f"{Fore.RED}Could not understand the command. Scanning all users by default.")
        users = get_all_users(conn, args.base_dn)

    report = []
    for user in users:
        findings = []
        if check_password_never_expires(user):
            findings.append(f"{Fore.YELLOW}Password Never Expires{Style.RESET_ALL}")
        if check_disabled_account(user):
            findings.append(f"{Fore.RED}Account Disabled{Style.RESET_ALL}")
        if check_spn_set(user):
            findings.append(f"{Fore.MAGENTA}SPN Set (Kerberoasting){Style.RESET_ALL}")
        if findings:
            report.append([
                user.sAMAccountName.value,
                user.userPrincipalName.value if 'userPrincipalName' in user else '',
                ", ".join(findings)
            ])

    print(f"\n{Fore.CYAN}=== Misconfiguration Report ==={Style.RESET_ALL}")
    if report:
        print(tabulate(report, headers=["Username", "UPN", "Findings"]))
    else:
        print(f"{Fore.GREEN}No misconfigurations found for the selected scope.")

if __name__ == '__main__':
    main()
