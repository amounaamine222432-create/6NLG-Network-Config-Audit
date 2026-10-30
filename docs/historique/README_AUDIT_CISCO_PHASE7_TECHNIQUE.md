# NetAudit / 6NLG - rapport CIS technique enrichi (phase 7)

Cette mise à jour conserve les trois étapes de la chaîne **configuration Cisco IOS -> parsing -> normalisation IR -> moteur CIS** et les **deux rapports PDF**. Elle ajoute une présentation technique moderne dans l'interface Flask, l'aperçu HTML et le rapport PDF d'audit.

## Pour chaque contrôle CIS (39 sur 39)

1. **Exigence CIS** : objectif précis du sous-ensemble sélectionné du benchmark Cisco IOS 15 v4.1.1.
2. **Configuration observée** : faits IR, commande IOS reconstruite uniquement pour certains cas, référence de ligne source lorsqu'elle existe, ou indication d'absence supposée.
3. **Analyse de l'écart** : explication spécifique au mécanisme vérifié et au verdict.
4. **Impact de sécurité** : risque associé à un écart, ou absence d'écart démontré pour PASS/N/A.
5. **Correction recommandée** : remédiation existante + exemple CLI **indicatif** + précaution de déploiement.
6. **Vérification** : commande `show` en lecture seule adaptée au contrôle.

Les preuves JSON sont toujours exportées mais **masquées par défaut dans l'interface**, car la synthèse interprétée est destinée à la lecture humaine.

## Sémantique des verdicts inchangée

- **PASS** : conformité statique démontrée pour le contrôle et l'entrée fournie.
- **FAIL** : écart démontré ou absence inférée quand l'utilisateur a déclaré la configuration complète.
- **UNKNOWN** : données insuffisantes, notamment configuration partielle ou interface WAN non renseignée.
- **NOT_APPLICABLE** : hors périmètre applicable.

Le moteur CIS d'origine n'a pas été modifié. Les commandes IOS de correction sont des **exemples non exécutés**, avec placeholders et précautions ; aucune collecte de secret ni modification réseau n'est déclenchée.

## Installation WSL sur le projet existant

Sauvegarder d'abord les fichiers personnalisés que l'archive pourrait remplacer.

```bash
cd ~/projet-6nlg/network-config-audit
source .venv/bin/activate
unzip /mnt/c/Users/LENOVO/Downloads/audit_cisco_ios_phase7_technique_6nlg.zip
python3 -m pip install -r requirements-web.txt
PYTHONPATH=parsers:.:scripts python3 -m unittest webapp.tests.test_webapp webapp.tests.test_webapp_cis_phase6 webapp.tests.test_webapp_cis_pipeline_pdf -v
PYTHONPATH=parsers:.:scripts python3 -m webapp
```

Ouvrir http://127.0.0.1:5050/#cis-audit

## Génération hors Flask d'un exemple sur la configuration volontairement non conforme

```bash
PYTHONPATH=parsers:.:scripts python3 scripts/export_cis_demo_pdf.py \
  data/cis_phase5/router_non_compliant.cfg \
  --profile L2 --assume-complete \
  --external-interface GigabitEthernet0/0
```

Les deux fichiers sont produits dans `output/pdf/` : cartographie parsing/IR et audit CIS détaillé. Avec la fixture ci-dessus, le moteur retourne toujours **2 PASS, 33 FAIL, 0 UNKNOWN, 4 NOT_APPLICABLE**. Sans désignation WAN, les deux contrôles ACL WAN passent à **UNKNOWN**, ce qui est attendu.

## Limites

Prototype pédagogique / audit statique, **pas** un benchmark CIS complet, une certification, un test d'état opérationnel ni une procédure de changement en production. Les exemples de commandes doivent être relus, adaptés à l'image IOS et validés avec les responsables d'exploitation.
