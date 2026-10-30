# Correctif 6NLG — Juniper IR v2.4 (28/10/2026)

Ce paquet **met à jour le projet existant** `network-config-audit`. Il ne le recrée pas.
Il suppose que l'intégration Flask Juniper et IR v2.3 sont déjà installées.

## Pourquoi ce correctif ?

L'IR v1 indiquait 12 feuilles non reprises pour `04_JUNOS_COMPLET_ROUTAGE_VRF.conf`,
et l'extracteur de fonctionnalités v2 en indiquait encore 8 : ces nombres sont
des **vues indépendantes qui se chevauchent**. Il était incorrect de les
additionner ou d'en déduire 20 feuilles réellement perdues. La couverture
consolidée partage désormais l'**AST réellement fourni par les bibliothèques
tierces** entre les trois étapes ; elle calcule l'union exacte des identifiants
de feuilles normalisées, sans déduire la sémantique d'une commande non prise en
charge.

## Changements

1. **Normalisation des politiques Junos** :
   - définitions statiques `policy-options prefix-list NAME { prefix; }`
     exposées dans `policies.junos_prefix_lists` ;
   - conditions `from prefix-list NAME` et
     `from prefix-list-filter NAME exact|longer|orlonger` exposées comme
     **références Junos**, sans les confondre avec les ACL/prefix-list Cisco ;
   - références non résolues et `apply-path` dynamique restent signalées ;
     aucun effet réseau opérationnel n'est inféré.
2. **Couverture consolidée** :
   - `combined_total_leaves`, `combined_modeled_leaves`,
     `combined_unmodeled_leaves`, `combined_unmodeled_by_section` dans
     `diagnostics.source_only_counts` ;
   - maintien **sans modification** des compteurs distincts IR v1 et IR v2 ;
   - exclusion des commentaires explicites du décompte ;
   - noms de sections inconnues anonymisés (`other`) dans les diagnostics.
3. **Fonctionnalités Junos** : présence du service SSH simple `ssh;`
   représentée comme `junos_details.auxiliary.system.ssh_configured` ;
   aucune hypothèse sur une version SSH ou une session réelle.
4. **Flask** : bilan de couverture consolidé dans le tableau et le rapport
   HTML, inventaire des préfixes Junos, compteur d'en-tête corrigé.
5. **Validation** : sept tests de non-régression supplémentaires ;
   un test Flask sur l'import des quatre fichiers ; quatre fixtures incluses.

## Installation sûre sous WSL Ubuntu

Depuis le répertoire du projet existant :

```bash
cd ~/projet-6nlg/network-config-audit
source .venv/bin/activate
```

Sauvegardez **avant d'extraire**, car l'archive remplace les fichiers indiqués
ci-dessous. Cette archive contient uniquement des fichiers de code de
normalisation, schéma, interface et tests ; elle ne touche pas aux corpus.

```bash
tar -czf ../network-config-audit-junos-v24-before.tar.gz \
  normalizers/junos_tree_loader.py \
  normalizers/juniper_ir_adapter.py \
  normalizers/juniper_features_ir_v2.py \
  normalizers/policy_ir_v2.py \
  schemas/network_device_ir_v2.schema.json \
  webapp/app.py webapp/juniper_adapter.py \
  webapp/templates/report_juniper.html \
  webapp/static/js/app.js
```

Après téléchargement du ZIP dans `C:\Users\LENOVO\Downloads` :

```bash
unzip -o \
  "/mnt/c/Users/LENOVO/Downloads/6NLG_Juniper_IR_V24_Correctif.zip" \
  -d .
```

## Tests à lancer

```bash
PYTHONPATH=parsers:. python3 -m unittest discover \
  -s tests -p 'test_*.py' -v

PYTHONPATH=parsers:. python3 -m unittest discover \
  -s webapp/tests -p 'test_*.py' -v

PYTHONPATH=parsers:. python3 -m webapp
```

Ouvrir ensuite `http://127.0.0.1:5000`, choisir **Juniper Junos / SRX**,
importer les quatre fichiers `.conf`/`.txt`, et consulter parsing, IR et bilan.

## Résultats mesurés sur les quatre exemples synthétiques

| Fichier | Feuilles AST utiles | Couverture combinée |
| --- | ---: | ---: |
| 01 — base | 7 | 7/7 |
| 02 — SRX policies/NAT, `display set` | 23 | 23/23 |
| 03 — OSPF/BGP | 22 | 22/22 |
| 04 — multi-protocoles/VRF | 33 | 33/33 |

Ces nombres ne signifient **pas** qu'une configuration est correctement
applicable à tout modèle Juniper ni que le réseau est opérationnel.
Le statut IR reste volontairement `partial` pour préserver cette limite.

Sur les corpus externes de notre copie de travail, des feuilles restent
réellement non couvertes après union : Batfish EVPN (12), Junosphere (12),
extrait SRX (24). Ces valeurs sont un indicateur local de progrès, **pas**
une couverture générale de Junos.

## Source de vérification sémantique

- Documentation Juniper :
  https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/concept/policy-configuring-prefix-lists-for-use-in-routing-policy-match-conditions.html

## Rappel méthodologique

La validation finale doit inclure un corpus indépendant du développement,
des résultats de référence par commande, des tests de modifications adverses
et une séparation stricte entre : reconnaissance syntaxique, normalisation,
applicabilité à la plateforme, validation opérationnelle et règles d'audit.
