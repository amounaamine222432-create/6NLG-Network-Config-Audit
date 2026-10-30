# Mise à jour ciblée — Rapport HTML détaillé NetAudit (6NLG)

Cette archive **complète l'interface Flask déjà installée** dans
`~/projet-6nlg/network-config-audit`.

Elle ne remplace pas le parseur, le normaliseur IR, les schémas, les scripts
d'audit, les données ou les tests historiques du projet.

## Contenu de la mise à jour

```text
webapp/app.py                         # adapte la génération HTML
webapp/detailed_report.py             # extraits sûrs reconstitués depuis IR
webapp/templates/report_detailed.html # bilan graphique autonome / imprimable
webapp/tests/test_webapp.py           # 12 tests d'intégration Flask
```

## Installer dans ton dépôt WSL

1. Arrête Flask (Ctrl+C dans le terminal qui exécute `python3 -m webapp`).
2. Depuis Ubuntu :

```bash
cd ~/projet-6nlg/network-config-audit

# Sauvegarder les fichiers Web existants avant l'import.
cp webapp/app.py webapp/app.py.avant_bilan_v2
cp webapp/tests/test_webapp.py webapp/tests/test_webapp.py.avant_bilan_v2

# Regarder les fichiers de l'archive avant l'extraction.
unzip -l "/mnt/c/Users/LENOVO/Downloads/6NLG_Rapport_HTML_Detaille_MAJ.zip"

# Mettre à jour les quatre chemins Web listés ci-dessus.
unzip -o "/mnt/c/Users/LENOVO/Downloads/6NLG_Rapport_HTML_Detaille_MAJ.zip" -d .

# Utiliser les dépendances Flask/Waitress déjà installées.
source .venv/bin/activate

# Vérifier la nouvelle interface.
python3 -m unittest discover -s webapp/tests -p 'test_*.py' -v

# Redémarrer le site.
python3 -m webapp
```

3. Ouvre **http://localhost:5050**.
4. Importe un ou plusieurs fichiers `.cfg`, lance l'analyse, puis clique sur
   **Rapport HTML**.

Le rapport HTML contient désormais, pour chaque équipement :

1. Une synthèse du routeur, des fonctionnalités et de la couverture du parsing.
2. Les interfaces, leur description, leur adresse IPv4/CIDR, leurs VLAN,
   ACL, VRF, NAT et état administratif déclaré.
3. OSPF : ID de processus, Router ID, sélecteurs réseau/wildcard/area,
   interfaces passives, paramètres reconstitués.
4. BGP : AS local/distant, voisins, réseaux annoncés déclarativement,
   politiques, paramètres reconstitués.
5. Routes statiques, ACL, prefix-lists et route-maps.
6. DHCP, NAT/PAT, VLAN, SNMP, Syslog, NTP, SSH et administration distante.
7. Les résultats des contrôles d'audit et les recommandations.

Pour sauvegarder le rapport en PDF, **ouvre le fichier HTML téléchargé puis
utilise Ctrl+P** (Imprimer → Enregistrer au format PDF).

**Note méthodologique :** les extraits sont générés à partir des *données
normalisées IR* ; ils ne constituent **pas** une transcription intégrale ni
une configuration prête à redéployer. Cela permet de retirer les secrets
SNMP/BGP/comptes locaux et d'indiquer ce que le parseur ne connaît pas.
L'état opérationnel n'est pas inféré depuis les seules commandes déclarées.
