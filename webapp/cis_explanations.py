"""Human-readable, non-decisional security guidance for the 39 laboratory checks.

This file is not a second CIS engine: it never changes a rule result. IOS
commands are illustrative templates, and never carry collected credentials.
"""

from __future__ import annotations


# check: (impact, illustrative configuration, read-only validation, precaution)
GUIDANCE = {
    "aaa_new_model": ("Sans AAA centralisé, les accès administratifs peuvent échapper à une politique d'authentification cohérente.", "aaa new-model", "show running-config | include ^aaa new-model", "Prévoir un accès console de secours avant d'activer AAA."),
    "vty_ssh_only": ("Telnet transmet l'administration sans chiffrement et expose les identifiants aux interceptions.", "line vty 0 4\n transport input ssh", "show running-config | section line vty", "Vérifier SSH, les clés et les comptes avant de désactiver Telnet ; couvrir toutes les plages VTY."),
    "console_exec_timeout": ("Une session console laissée ouverte permet des actions non autorisées sur le routeur.", "line con 0\n exec-timeout 10 0", "show running-config | section line con", "Adapter le délai aux opérations de maintenance et au mode de secours."),
    "vty_exec_timeout": ("Une session VTY inactive peut être réutilisée par un tiers ayant accès au terminal.", "line vty 0 4\n exec-timeout 10 0", "show running-config | section line vty", "Appliquer le réglage à toutes les plages VTY réellement configurées."),
    "exec_banner_present": ("L'absence d'avertissement réduit la clarté des conditions d'accès à un système administré.", "banner exec ^Acces reserve aux administrateurs autorises^", "show running-config | include ^banner exec", "Faire valider le texte par l'organisation ; ne pas divulguer d'information sensible."),
    "login_banner": ("La politique d'avertissement légal n'est pas affichée avant l'authentification.", "banner login ^Acces autorise uniquement^", "show running-config | include ^banner login", "Faire approuver la bannière et vérifier son affichage avant la connexion."),
    "motd_banner": ("Le dispositif ne fournit pas l'avertissement d'accès attendu à l'ouverture de session.", "banner motd ^Systeme supervise - acces restreint^", "show running-config | include ^banner motd", "Éviter les informations techniques internes dans les bannières."),
    "enable_secret_present": ("Un mode privilégié insuffisamment protégé facilite l'élévation de privilèges.", "enable secret <SECRET_A_DEFINIR>", "show running-config | include ^enable secret", "Générer un secret robuste hors du rapport ; ne jamais copier la valeur dans les journaux."),
    "local_user_secrets": ("Les déclarations username password utilisent un mécanisme moins adapté que username secret.", "username <COMPTE> secret <SECRET_A_DEFINIR>", "show running-config | include ^username", "Préparer une méthode de secours ; ne pas exposer les identifiants ou secrets."),
    "snmp_no_rw": ("Une communauté SNMP RW peut permettre une modification distante non autorisée de paramètres.", "no snmp-server community <COMMUNAUTE_RW>", "show running-config | include ^snmp-server community", "Vérifier les usages de supervision ; migrer vers SNMPv3 et une politique de moindre privilège."),
    "snmp_v3_priv": ("Un groupe SNMPv3 sans priv peut exposer des informations de supervision en clair.", "snmp-server group <GROUPE> v3 priv", "show snmp group", "Valider les utilisateurs, l'authentification et le chiffrement pris en charge avant changement."),
    "ssh_version2": ("SSH version 1 possède des faiblesses cryptographiques et ne doit pas servir à administrer le routeur.", "ip ssh version 2", "show ip ssh", "Vérifier compatibilité des clients et existence de clés SSH utilisables."),
    "syslog_buffer": ("Un tampon absent ou trop petit peut faire perdre les événements nécessaires aux investigations.", "logging buffered 64000 informational", "show logging", "Dimensionner la mémoire selon la plateforme et le volume d'événements."),
    "syslog_host": ("Sans collecteur distant, les traces peuvent disparaître après panne ou compromission locale.", "logging host <IP_COLLECTEUR>", "show logging", "Autoriser uniquement un collecteur de confiance et vérifier l'acheminement réseau."),
    "syslog_informational": ("Un niveau trop restrictif peut masquer des événements de sécurité utiles.", "logging trap informational", "show logging", "Ajuster le volume et la rétention avec l'équipe SOC."),
    "syslog_source_present": ("Une adresse source instable complique la corrélation et le filtrage des messages Syslog.", "logging source-interface Loopback0", "show running-config | include ^logging source-interface", "Employer une interface réellement présente, stable et joignable du collecteur."),
    "ntp_auth_enabled": ("Sans authentification NTP, une source de temps usurpée peut fausser les journaux et analyses.", "ntp authenticate", "show running-config | include ^ntp authenticate", "Distribuer les clés de manière sécurisée et vérifier les capacités du serveur NTP."),
    "ntp_auth_keys": ("L'absence de clés NTP empêche de vérifier l'origine de la synchronisation temporelle.", "ntp authentication-key <ID> md5 <CLE_SECRETE>", "show running-config | include ^ntp authentication-key", "Ne jamais enregistrer ou afficher la valeur de clé dans le rapport."),
    "ntp_trusted_keys": ("Une clé configurée mais non approuvée ne garantit pas la confiance accordée au pair NTP.", "ntp trusted-key <ID>", "show running-config | include ^ntp trusted-key", "Faire correspondre l'identifiant à la politique de clés du serveur."),
    "ntp_server_keys": ("Un serveur NTP sans association à une clé peut rester non authentifié.", "ntp server <IP_NTP> key <ID>", "show ntp associations", "Confirmer la présence du serveur et de la clé de confiance avant modification."),
    "ntp_servers": ("Sans synchronisation fiable, les horodatages des incidents et des journaux deviennent incohérents.", "ntp server <IP_NTP>", "show ntp associations", "Choisir une source autorisée et vérifier le chemin réseau et les ACL."),
    "ntp_loopback_source": ("Une source NTP variable peut provoquer des ruptures de politique ou de connectivité.", "ntp source Loopback0", "show running-config | include ^ntp source", "La Loopback doit exister, être routable et acceptée par le serveur NTP."),
    "source_routing_disabled": ("Le source routing IP peut faciliter le contournement de chemins de filtrage prévus.", "no ip source-route", "show running-config | include ^no ip source-route", "Vérifier les dépendances éventuelles d'applications historiques."),
    "proxy_arp_disabled": ("Proxy ARP peut exposer le routeur à des flux ou résolutions d'adresse inattendus.", "interface <INTERFACE>\n no ip proxy-arp", "show ip interface", "Évaluer l'impact sur les hôtes utilisant historiquement Proxy ARP."),
    "no_tunnel_interfaces": ("Un tunnel non autorisé peut contourner la segmentation ou créer un chemin réseau opaque.", "! Examiner et supprimer uniquement les tunnels injustifies", "show interfaces tunnel", "Ne jamais supprimer un tunnel légitime sans revue de topologie et de service."),
    "bgp_neighbor_password": ("Sans authentification du voisin BGP, des sessions de routage peuvent être usurpées.", "router bgp <AS>\n neighbor <IP_VOISIN> password <SECRET>", "show ip bgp neighbors", "Coordonner la clé avec le voisin ; prévoir la convergence et le risque de coupure."),
    "aaa_login_default": ("Une liste login utilisant none peut autoriser des accès sans authentification.", "aaa authentication login default local", "show running-config | include ^aaa authentication login", "Vérifier l'existence de comptes de secours avant de modifier la méthode par défaut."),
    "aaa_enable_default": ("La transition vers le mode privilégié peut être insuffisamment authentifiée.", "aaa authentication enable default enable", "show running-config | include ^aaa authentication enable", "Tester la méthode de secours sur console avant la mise en service."),
    "aaa_line_console": ("Une console non liée à une liste AAA peut contourner la politique de connexion.", "line con 0\n login authentication default", "show running-config | section line con", "S'assurer que la liste AAA référencée existe et ne verrouille pas l'accès de secours."),
    "aaa_line_tty": ("Une ligne TTY non protégée peut ouvrir une voie d'administration non contrôlée.", "line tty <PLAGE>\n login authentication default", "show running-config | section line tty", "N'appliquer que si des lignes TTY sont présentes et réellement utilisées."),
    "aaa_line_vty": ("Des lignes VTY sans liste AAA cohérente peuvent contourner le contrôle des comptes.", "line vty 0 4\n login authentication default", "show running-config | section line vty", "Vérifier toutes les plages VTY et la disponibilité de la liste AAA."),
    "vty_restricting_acl": ("Une gestion accessible depuis des sources non fiables augmente l'exposition aux attaques.", "ip access-list standard VTY-MGMT\n permit <RESEAU_ADMIN> <WILDCARD>\n deny any", "show ip access-lists VTY-MGMT", "Ne bloquer les sources qu'après validation du plan d'adressage d'administration."),
    "vty_access_class": ("Une ACL déclarée mais non appliquée ne filtre pas les connexions administratives.", "line vty 0 4\n access-class VTY-MGMT in", "show running-config | section line vty", "Appliquer à toutes les plages VTY et conserver un accès d'urgence."),
    "external_antispoof_acl": ("L'acceptation de sources privées ou réservées sur un WAN public peut faciliter l'usurpation d'origine.", "ip access-list extended WAN-IN\n deny ip <PLAGE_INTERDITE> <WILDCARD> any\n permit ip <FLUX_LEGITIMES> any", "show ip access-lists WAN-IN", "Sélectionner les réseaux à refuser selon l'adressage réel ; ne pas copier une ACL générique en production."),
    "external_inbound_acl": ("Sans filtrage entrant sur le WAN, des flux indésirables peuvent atteindre le réseau.", "interface <WAN>\n ip access-group WAN-IN in", "show ip interface <WAN>", "Préparer et vérifier l'ACL avant association ; risque de couper le trafic légitime."),
    "eigrp_interface_keychain": ("L'absence de chaîne de clés EIGRP facilite l'injection de voisinages non autorisés.", "interface <INTERFACE_EIGRP>\n ip authentication key-chain eigrp <AS> <CHAINE>", "show ip eigrp interfaces detail", "Créer préalablement une chaîne valide et coordonner les clés avec les voisins."),
    "eigrp_interface_md5": ("Sans authentification EIGRP, des annonces de routage non fiables peuvent être acceptées.", "interface <INTERFACE_EIGRP>\n ip authentication mode eigrp <AS> md5", "show ip eigrp interfaces detail", "Activer conjointement une key-chain compatible sur tous les voisins concernés."),
    "ospf_area_md5": ("Sans protection des adjacences OSPF, un pair non autorisé peut annoncer des routes.", "router ospf <PID>\n area <AREA> authentication message-digest", "show ip ospf interface", "Coordonner les clés et le mode d'authentification de toutes les interfaces de la zone."),
    "ospf_interface_md5": ("Une interface OSPF sans clé attendue peut participer à un voisinage non authentifié ou perdre son adjacence.", "interface <INTERFACE_OSPF>\n ip ospf message-digest-key <ID> md5 <SECRET>", "show ip ospf interface", "Distribuer les clés hors rapport ; une incohérence coupe les adjacences OSPF."),
}

MECHANISMS = {
    "aaa_new_model": "L'activation de aaa new-model est la condition de base des méthodes AAA IOS.",
    "vty_ssh_only": "Chaque plage VTY est inspectée ; la présence de telnet ou d'un transport non exclusivement SSH provoque un écart.",
    "console_exec_timeout": "Le délai de la console doit être positif et ne pas dépasser 600 secondes ; 0 désactive l'expiration.",
    "vty_exec_timeout": "Toutes les plages VTY doivent imposer une expiration positive d'au plus 600 secondes.",
    "exec_banner_present": "Une bannière EXEC doit être visible dans la configuration complète.",
    "login_banner": "La bannière LOGIN est contrôlée indépendamment des bannières EXEC et MOTD.",
    "motd_banner": "Le message MOTD est une directive distincte des bannières LOGIN et EXEC.",
    "enable_secret_present": "La présence de enable secret est vérifiée séparément de enable password.",
    "local_user_secrets": "Les comptes déclarés avec username password sont distingués des comptes username secret.",
    "snmp_no_rw": "Les communautés SNMP donnant des droits d'écriture sont dénombrées ; la simple existence de SNMP n'est pas une non-conformité.",
    "snmp_v3_priv": "Les groupes SNMPv3 présents doivent utiliser authPriv (priv) ; l'absence de groupe peut rendre le contrôle non applicable.",
    "ssh_version2": "La directive ip ssh version est comparée à la valeur 2 ; une valeur 1 expose un mode obsolète.",
    "syslog_buffer": "La présence et la capacité déclarée du tampon Syslog sont contrôlées.",
    "syslog_host": "Au moins une destination distante autorisée doit être déclarée pour l'envoi des journaux.",
    "syslog_informational": "Le niveau de gravité du flux Syslog distant est comparé au seuil informational.",
    "syslog_source_present": "Une interface source explicite est attendue pour conserver une identité stable des événements.",
    "ntp_auth_enabled": "L'authentification NTP doit être activée explicitement, indépendamment de la présence des serveurs.",
    "ntp_auth_keys": "Les identifiants de clés NTP sont vérifiés sans lire ni publier les valeurs secrètes.",
    "ntp_trusted_keys": "Les clés autorisées doivent être explicitement marquées trusted-key.",
    "ntp_server_keys": "Chaque association NTP visée doit référencer une clé d'authentification attendue.",
    "ntp_servers": "La présence de serveurs NTP autorisés est contrôlée avant de juger l'association et la synchronisation.",
    "ntp_loopback_source": "La source NTP doit référencer une Loopback présente et compatible avec le routage.",
    "source_routing_disabled": "Le paramètre global ip source-route ne doit pas autoriser le routage imposé par l'émetteur.",
    "proxy_arp_disabled": "Les interfaces concernées doivent explicitement neutraliser la fonction Proxy ARP.",
    "no_tunnel_interfaces": "Les interfaces Tunnel sont recherchées ; leur absence est une conclusion statique conditionnée à la complétude.",
    "bgp_neighbor_password": "L'authentification est vérifiée pour chaque voisin BGP déclaré.",
    "aaa_login_default": "Une liste login default doit exister et ne pas comporter la méthode none.",
    "aaa_enable_default": "La liste AAA enable default doit définir une méthode d'authentification valide.",
    "aaa_line_console": "La console doit référencer une liste AAA login effectivement définie.",
    "aaa_line_tty": "Chaque ligne TTY applicable doit référencer une liste AAA login valide.",
    "aaa_line_vty": "L'intégralité des plages VTY doit être liée à une liste AAA login existante.",
    "vty_restricting_acl": "Une ACL de gestion est considérée restrictive seulement si elle limite les origines autorisées.",
    "vty_access_class": "Chaque plage VTY doit appliquer la liste de contrôle de gestion en entrée.",
    "external_antispoof_acl": "Sur l'interface WAN indiquée, les refus anti-usurpation doivent précéder les permissions générales.",
    "external_inbound_acl": "L'ACL entrante doit être effectivement associée à l'interface WAN désignée.",
    "eigrp_interface_keychain": "Les interfaces participant à EIGRP doivent être liées à une chaîne de clés définie.",
    "eigrp_interface_md5": "Le mode MD5 doit être actif sur les interfaces EIGRP concernées.",
    "ospf_area_md5": "Les zones OSPF participantes doivent imposer le mode message-digest attendu.",
    "ospf_interface_md5": "Les interfaces OSPF participantes doivent disposer de clés message-digest compatibles.",
}


def enrich_explanation(finding: dict, check: str) -> None:
    """Add six educational fields without affecting the source CIS result."""
    impact, example, verification, precaution = GUIDANCE.get(check, (
        "Conséquence à confirmer avec l'équipe réseau.",
        "! Configuration illustrative non disponible",
        "show running-config",
        "Validation manuelle nécessaire avant tout changement.",
    ))
    status = finding.get("status", "UNKNOWN")
    observed = finding.get("observed_summary") or "Aucune observation exploitable."
    mechanism = MECHANISMS.get(check, "La conformité dépend de la politique de sécurité applicable.")
    if status == "PASS":
        analysis = f"Contrôle satisfait sur les faits statiques disponibles. {mechanism} Constat : {observed}"
    elif status == "FAIL":
        analysis = f"Critère non satisfait. {mechanism} Constat : {observed}"
    elif status == "UNKNOWN":
        analysis = f"Preuve insuffisante pour conclure. {mechanism} Information manquante : {observed}"
    elif status == "NOT_APPLICABLE":
        analysis = "Le contrôle n'est pas applicable au périmètre déclaré ; aucune défaillance n'est démontrée."
    else:
        analysis = "Aucun verdict technique exploitable pour ce contrôle dans le périmètre sélectionné."
    evidence = finding.get("evidence") or {}
    lines = []
    def scan(value):
        if isinstance(value, dict):
            if isinstance(value.get("source_line"), int):
                lines.append(value["source_line"])
            if isinstance(value.get("source_lines"), list):
                lines.extend(x for x in value["source_lines"] if isinstance(x, int))
            for nested in value.values():
                if isinstance(nested, (dict, list)):
                    scan(nested)
        elif isinstance(value, list):
            for nested in value:
                scan(nested)
    scan(evidence)
    unique_lines = sorted(set(lines))[:12]
    location = ("Ligne(s) de la source : " + ", ".join(str(x) for x in unique_lines)) if unique_lines else (
        "Absence inférée depuis une configuration déclarée complète" if finding.get("evidence_basis") == "assumed_absence"
        else "Emplacement non identifié dans la preuve structurée")
    if check == "vty_ssh_only" and evidence.get("vty_lines"):
        observed_command = "; ".join(
            f"{item.get('line_id', 'VTY')} : transport input {' '.join(item.get('transport_input') or ['<ABSENT>'])}"
            for item in evidence["vty_lines"])
    elif check == "ssh_version2" and evidence.get("ssh_version") is not None:
        observed_command = f"ip ssh version {evidence['ssh_version']}"
    elif check in {"console_exec_timeout", "vty_exec_timeout"} and evidence.get("lines"):
        observed_command = "; ".join(
            f"{item.get('line_id', 'ligne')} : exec-timeout "
            + (f"{int(item['seconds']) // 60} {int(item['seconds']) % 60}"
               if isinstance(item.get('seconds'), (int, float)) else "non observé")
            for item in evidence["lines"])
    else:
        observed_command = "Aucune commande brute exportée ; constat calculé à partir de l'IR expurgée."
    finding.update({
        "technical_analysis": analysis,
        "security_impact": impact if status == "FAIL" else (
            "Risque théorique associé à une non-conformité : " + impact if status == "UNKNOWN" else
            "Pas d'écart démontré pour ce contrôle dans le périmètre audité."),
        "ios_config_observed": observed_command,
        "source_location": location,
        "remediation_example": example if status == "FAIL" else "Aucune modification proposée pour ce verdict.",
        "remediation_caution": precaution if status == "FAIL" else "Ne pas modifier une configuration sur la seule base de ce verdict.",
        "verification_command": verification,
    })
