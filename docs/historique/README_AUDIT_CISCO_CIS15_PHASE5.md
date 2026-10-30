# Phase 5 — contrôles d'accès, ACL et authentification OSPF/EIGRP

Cette livraison complète **sans effacer la phase 4** les 26 règles du catalogue
`cis_ios15_v4.1.1_extended_lab.json` et fournit un nouveau catalogue
`cis_ios15_v4.1.1_phase5_lab.json` comportant **39 règles** expérimentales,
référencées sur le benchmark archivé **CIS Cisco IOS 15 v4.1.1**. Cela ne
constitue ni la couverture intégrale du benchmark, ni une certification CIS.

## Livrables

- `data/cis_phase5/router_compliant.cfg` : configuration de laboratoire comprenant
  les exigences étudiées ; secrets fictifs et adresses de documentation.
- `data/cis_phase5/router_non_compliant.cfg` : défauts volontaires et explicites.
- `data/cis_phase5/router_partial.cfg` : extrait incomplet, pour conserver `UNKNOWN`.
- 13 contrôles additionnels : AAA 1.1.2–1.1.6 ; ACL VTY 1.2.4–1.2.5 ;
  ACL WAN 3.2.1–3.2.2 ; EIGRP 3.3.1.8–3.3.1.9 ;
  OSPF 3.3.2.1–3.3.2.2.
- Parsing et IR enrichis : méthodes AAA, `access-class`, area OSPF,
  clés MD5 OSPF (présence uniquement), EIGRP classique/nommé partiel,
  chaînes de clés (présence uniquement).
- Collecteur SSH `show` sur liste blanche, avec host key vérifiée et sortie
  **résumée uniquement** ; aucune configuration n'est modifiée.

## Installer dans Ubuntu WSL

Depuis le répertoire du projet :

```bash
cd ~/projet-6nlg/network-config-audit
source .venv/bin/activate
unzip -l /mnt/c/Users/LENOVO/Downloads/audit_cisco_ios_phase5_6nlg.zip
unzip /mnt/c/Users/LENOVO/Downloads/audit_cisco_ios_phase5_6nlg.zip
PYTHONPATH=parsers:.:scripts python3 -m unittest discover -s tests -p 'test_*.py' -q
```

L'archive est une **surcouche de fichiers** et non un dépôt Git complet.
Si le dossier du projet n'est pas un dépôt (`fatal: not a git repository`),
ne pas initialiser, écraser ou réinitialiser un dépôt sans décider de son
organisation. Sauvegarder les fichiers personnalisés avant de confirmer les
remplacements proposés par `unzip`.

## Trois audits reproductibles

```bash
# Configuration de démonstration conforme (profil L2 et rôle WAN explicités)
PYTHONPATH=parsers:. python3 scripts/run_cis_ios15_audit.py \
  data/cis_phase5/router_compliant.cfg --profile L2 --assume-complete \
  --external-interface GigabitEthernet0/0 \
  --output reports/cis_phase5_ok.json

# Cas vulnérable : échecs attendus
PYTHONPATH=parsers:. python3 scripts/run_cis_ios15_audit.py \
  data/cis_phase5/router_non_compliant.cfg --profile L2 --assume-complete \
  --external-interface GigabitEthernet0/0 \
  --output reports/cis_phase5_fail.json

# Extrait partiel : ne PAS ajouter --assume-complete
PYTHONPATH=parsers:. python3 scripts/run_cis_ios15_audit.py \
  data/cis_phase5/router_partial.cfg --profile L2 \
  --output reports/cis_phase5_partial.json
```

Résultat attendu du cas conforme : **36 PASS, 0 FAIL, 0 UNKNOWN,
3 NOT_APPLICABLE** (TTY, SNMP RW, BGP sans voisins). Ces nombres s'appliquent
uniquement au jeu de démonstration et à ses hypothèses.

`--external-interface` est indispensable pour évaluer les règles WAN 3.2.1
et 3.2.2. Sans connaissance explicite de l'interface externe, le moteur
répond `UNKNOWN` et n'infère pas une topologie à partir d'un nom de port.

## Collecte opérationnelle limitée à SHOW

### Préconditions

1. Obtenir l'autorisation de consulter l'équipement.
2. Créer/utiliser un compte IOS ayant les droits de **consultation uniquement**.
3. Faire approuver et enregistrer la **clé hôte SSH** dans `known_hosts`.
   La vérification SSH est stricte : aucune clé inconnue n'est approuvée
   automatiquement.
4. Installer la dépendance facultative :

```bash
python3 -m pip install -r requirements-show.txt
```

### Prévisualiser et exécuter

```bash
# Ne se connecte pas, n'ouvre aucune session réseau
PYTHONPATH=parsers:. python3 scripts/collect_ios_show.py \
  --host 192.0.2.10 --username lecture --expected-hostname R-PHASE5-OK \
  --output reports/r_phase5_show_evidence.json --dry-run

# À remplacer par l'IP et le nom réels d'un routeur autorisé
PYTHONPATH=parsers:. python3 scripts/collect_ios_show.py \
  --host 192.0.2.10 --username lecture --expected-hostname R-PHASE5-OK \
  --output reports/r_phase5_show_evidence.json
```

**Attention** : `192.0.2.10` est une adresse illustrative non routable
sur Internet, à remplacer explicitement. Le programme demande le mot de
passe via une saisie masquée, n'emploie pas le mode configuration et ne
sauvegarde **aucune sortie brute**. Seuls des faits résumés et limités sont
conservés. Les commandes sont fixées dans `audit_engine/show_evidence.py` :
`show version`, `show ip ssh`, `show line`, `show ip ospf interface`,
`show ip eigrp interfaces detail`, `show ip access-lists`, `show ip interface`.

### Joindre les preuves au rapport

```bash
PYTHONPATH=parsers:. python3 scripts/run_cis_ios15_audit.py \
  routeur_reel.cfg --profile L2 \
  --show-evidence reports/r_phase5_show_evidence.json \
  --external-interface GigabitEthernet0/0 \
  --output reports/routeur_reel_phase5.json
```

La preuve `show ip ssh` peut résoudre le statut `UNKNOWN` de la règle
SSH 2.1.1.2 **uniquement si** `show version` a permis d'identifier le même
hostname que dans la configuration analysée et si la collecte date de moins
de 24 heures. Les autres sorties alimentent
des observations descriptives, sans transformer automatiquement des
informations incomplètes en `PASS`.

## Limites connues et interprétation

- La classification des interfaces OSPF/EIGRP s'appuie seulement sur les
  `network` déclarés, les IP statiques et certaines commandes d'interface.
  Les modes nommés EIGRP, les VRF, le filtrage complexe et les topologies
  dynamiques restent partiellement couverts : `UNKNOWN` si le contexte manque.
- Les règles ACL WAN valident une **liste exacte** de refus de sources
  spécifiques issue du benchmark. Elles ne remplacent pas un calcul exhaustif
  de politique, ne prouvent pas l'efficacité du chemin réseau et doivent être
  confrontées à la topologie réelle.
- Un `PASS` sur `ip authentication ... md5` signifie que la **déclaration**
  syntaxique existe dans le périmètre étudié, pas que les voisins s'authentifient
  effectivement, ni que MD5 est le meilleur mécanisme cryptographique actuel.
- Il n'y a **pas de connexion SSH lors des tests unitaires**.
- Ne jamais publier les configurations réelles, les clés ou les rapports
  opérationnels sans revue de confidentialité.

## Références

- CIS Cisco IOS 15 Benchmark v4.1.1 (PDF archivé fourni par le projet),
  pages 15–23, 41–43, 159–161, 178–184.
- Netmiko : https://github.com/ktbyers/netmiko — bibliothèque SSH réseau.
