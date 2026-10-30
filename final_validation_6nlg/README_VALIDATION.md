# Validation finale Cisco IOS 15 — projet 6NLG

Deux configurations de laboratoire synthétiques (aucun vrai mot de passe) :

- `01_R-FINAL-HARDENED.cfg` : AAA, SSH, ACL WAN/VTY, Syslog, DHCP, NAT, VRF/VLAN, OSPF, EIGRP authentifié, BGP, routes statiques. **30 PASS, 0 FAIL, 9 UNKNOWN** (profil L2, configuration non présumée complète).
- `02_R-FINAL-MIXED-RISK.cfg` : mêmes grandes familles avec faiblesses délibérées. **2 PASS, 16 FAIL, 21 UNKNOWN**.

## Installation dans WSL

Depuis `~/projet-6nlg/network-config-audit` :

```bash
unzip -n /mnt/c/Users/LENOVO/Downloads/6NLG_VALIDATION_FINALE_2_CONFIGS.zip
export PYTHONPATH="$PWD:$PWD/parsers:$PWD/scripts"
python3 final_validation_6nlg/export_final_validation.py --project .
```

Le script exécute **le parseur actif**, **le normaliseur actif**, puis **le moteur CIS actif** et écrit six JSON et six HTML dans `final_validation_6nlg/export/`.

## Inspection et copie vers Windows

```bash
ls -lh final_validation_6nlg/export/
python3 -m json.tool final_validation_6nlg/export/01_R-FINAL-HARDENED.ir.json | less
python3 -m json.tool final_validation_6nlg/export/02_R-FINAL-MIXED-RISK.audit.json | less
cp -r final_validation_6nlg/export /mnt/c/Users/LENOVO/Downloads/6NLG_Validation_Exports
```

Sur Windows, ouvrir les fichiers `*.html` avec le navigateur.

**Attention :** les HTML produits ici sont des vues complètes et autonomes des JSON, générées par un script terminal. Ce ne sont pas les modèles HTML de Flask. Pour vérifier précisément **l'interface officielle**, importer également les deux `.cfg` dans la page Flask et télécharger ses rapports HTML/PDF CIS.

**Interprétation des UNKNOWN :** en mode `complete_config=False`, une commande absente ne prouve généralement pas que le routeur est défaillant. Le benchmark mesure la reconnaissance et la normalisation, pas automatiquement la conformité effective ni la sécurité d'un routeur actif. N'utilisez pas ces configurations sur du matériel de production.
