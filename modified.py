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
    try:
        conn = Connection(server, user=user, password=password, authentication=NTLM, auto_bind=True)
        if not conn.bound:
            print("Invalid username or password.")
            return None
    except Exception as e:
        print(f"Failed to connect: {e}")
        return None
    return conn

def check_user_role(conn, username, base_dn):
    """Check what role the authenticated user has in AD"""
    try:
        # Search for the authenticated user to get their group memberships
        conn.search(base_dn, f'(sAMAccountName={username})', attributes=['memberOf', 'userAccountControl'])
        if not conn.entries:
            return "unknown"
        
        user_entry = conn.entries[0]
        groups = [str(group) for group in user_entry.memberOf.values] if user_entry.memberOf else []
        
        # Check for specific role groups
        if any('CN=Domain Admins' in group for group in groups):
            return "domain_admin"
        elif any('CN=Enterprise Admins' in group for group in groups):
            return "enterprise_admin"
        elif any('CN=Security Auditors' in group for group in groups):
            return "security_auditor"
        elif any('CN=Help Desk' in group for group in groups):
            return "help_desk"
        elif any('CN=Account Operators' in group for group in groups):
            return "account_operator"
        else:
            return "regular_user"
            
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Could not determine user role: {e}")
        return "unknown"

def get_role_permissions(user_role):
    """Define what each role can access"""
    permissions = {
        "domain_admin": {
            "can_audit_all": True,
            "can_see_all_users": True,
            "can_see_all_attributes": True,
            "description": "Full access to all security information"
        },
        "enterprise_admin": {
            "can_audit_all": True,
            "can_see_all_users": True,
            "can_see_all_attributes": True,
            "description": "Full access to all security information"
        },
        "security_auditor": {
            "can_audit_all": True,
            "can_see_all_users": True,
            "can_see_all_attributes": True,
            "description": "Full read access for security auditing"
        },
        "help_desk": {
            "can_audit_all": False,
            "can_see_all_users": False,
            "can_see_all_attributes": False,
            "description": "Limited access to user accounts in assigned OUs"
        },
        "account_operator": {
            "can_audit_all": False,
            "can_see_all_users": False,
            "can_see_all_attributes": False,
            "description": "Limited access to user accounts"
        },
        "regular_user": {
            "can_audit_all": False,
            "can_see_all_users": False,
            "can_see_all_attributes": False,
            "description": "Minimal access - own account only"
        },
        "unknown": {
            "can_audit_all": False,
            "can_see_all_users": False,
            "can_see_all_attributes": False,
            "description": "Unknown role - restricted access"
        }
    }
    return permissions.get(user_role, permissions["unknown"])

def get_all_users(conn, base_dn, user_role):
    """Get users based on role permissions"""
    permissions = get_role_permissions(user_role)
    
    if not permissions["can_see_all_users"]:
        print(f"{Fore.YELLOW}Role '{user_role}' does not have permission to view all users.")
        return []
    
    # ❌ NO role checking here
    conn.search(base_dn, '(objectClass=user)', attributes=['sAMAccountName', 'userAccountControl', 'pwdLastSet', 'lastLogon', 'memberOf', 'userPrincipalName', 'servicePrincipalName'])
    return conn.entries

def get_user_by_name(conn, base_dn, username, user_role):
    """Get specific user based on role permissions"""
    permissions = get_role_permissions(user_role)
    
    # Regular users can only see their own account
    if user_role == "regular_user":
        # Get the authenticated user's username from the connection
        try:
            conn.search(base_dn, f'(sAMAccountName={username})', attributes=['sAMAccountName', 'userAccountControl', 'pwdLastSet', 'lastLogon', 'memberOf', 'userPrincipalName', 'servicePrincipalName'])
            return conn.entries
        except Exception as e:
            print(f"{Fore.RED}Access denied: {e}")
            return []
    
    # Other roles can search for specific users
    if not permissions["can_see_all_users"]:
        print(f"{Fore.YELLOW}Role '{user_role}' does not have permission to search for other users.")
        return []
    
    search_filter = f'(sAMAccountName={username})'
    conn.search(base_dn, search_filter, attributes=['sAMAccountName', 'userAccountControl', 'pwdLastSet', 'lastLogon', 'memberOf', 'userPrincipalName', 'servicePrincipalName'])
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
    parser = argparse.ArgumentParser(description='AD Security Misconfiguration Auditor with Role-Based Access Control')
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
    print(f'\n{Fore.CYAN}Note: Available commands depend on your role permissions.')
    user_command = input('Enter your command: ')
    intent = interpret_command(user_command)

    print(f"{Fore.CYAN}[*] Connecting to AD server...")
    conn = connect_to_ad(args.server, args.username, args.password, args.domain)
    if conn is None:
        print(f"{Fore.RED}Could not connect to the AD server. Please check your credentials and network.")
        return  # or exit(1)
    print(f"{Fore.GREEN}[+] Connected!")

    # Determine user role
    user_role = check_user_role(conn, args.username, args.base_dn)
    print(f"{Fore.CYAN}[*] Authenticated as: {user_role.upper()}")
    permissions = get_role_permissions(user_role)
    print(f"{Fore.CYAN}[*] Role Permissions: {permissions['description']}")

    # Check if user has permission to perform security audits
    if not permissions["can_audit_all"]:
        print(f"{Fore.YELLOW}[!] Warning: Your role '{user_role}' has limited permissions.")
        if user_role == "regular_user":
            print(f"{Fore.YELLOW}[!] Regular users can only audit their own account.")
        elif user_role in ["help_desk", "account_operator"]:
            print(f"{Fore.YELLOW}[!] Your role may have limited access to user accounts.")

    if intent['action'] == 'scan_all':
        print(f"{Fore.GREEN}[*] Enumerating all users...")
        users = get_all_users(conn, args.base_dn, user_role)
    elif intent['action'] == 'scan_user':
        specific_user = intent['username']
        print(f"{Fore.GREEN}[*] Searching for user: {specific_user}")
        users = get_user_by_name(conn, args.base_dn, specific_user, user_role)
    else:
        print(f"{Fore.RED}Could not understand the command. Scanning all users by default.")
        users = get_all_users(conn, args.base_dn, user_role)

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
