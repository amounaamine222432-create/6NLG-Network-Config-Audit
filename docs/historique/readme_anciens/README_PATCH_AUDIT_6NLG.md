# Correctif moteur 6NLG - analyse CIS + cohérence

Installer ce paquet **depuis la racine** `~/projet-6nlg/network-config-audit`.

1. Sauvegarder les fichiers modifiés et vérifier `git status`.
2. Examiner les fichiers du ZIP : `unzip -l 6NLG_AMELIORATION_MOTEUR_AUDIT.zip`.
3. Appliquer : `unzip -o 6NLG_AMELIORATION_MOTEUR_AUDIT.zip` (écrase les chemins listés).
4. Activer `.venv` et exporter `PYTHONPATH="$PWD:$PWD/parsers:$PWD/normalizers"`.
5. Tester :

   ```bash
   python -m unittest discover -s tests -p 'test_*.py' -q
   python -m unittest discover -s webapp/tests -p 'test_*.py' -q
   python validation_reference_cis_39/run_validation.py .
   ```

6. Lancer Flask puis réimporter une configuration **dans l'onglet CIS** : les
   anciens exports ne seront pas modifiés rétroactivement.

## Modifications

- Les **39 verdicts CIS restent inchangés** : seul leur niveau d'impact
  indicatif (LOW/MEDIUM/HIGH pour FAIL) est ajouté au rapport.
- Le HTML affiche désormais explicitement les extraits IOS source expurgés
  déjà collectés, avec leurs numéros de ligne. Un extrait contextuel seul ne
  fait jamais foi pour la décision CIS.
- Ajout d'un **moteur complémentaire** `audit_engine/network_coherence.py` :
  ROUTE_CONFLICT, INVALID_DEFAULT_GATEWAY, ACL_RULE_SHADOWING, UNUSED_ACL.
- Les contrôles de cohérence sont dans une section séparée du HTML et du PDF ;
  ils n'entrent pas dans le décompte des 39 CIS.
- `REVIEW` signifie inspection humaine indispensable (ECMP, route récursive,
  ACL éventuellement employée par NAT/QoS/route-map). `UNKNOWN` indique un
  cas où le moteur ne dispose pas de la sémantique complète.
- Aucune commande de configuration n'est exécutée.

## Limites honnêtes

- Le contrôle ACL shadowing traite les ACL IPv4 standard ainsi que certains
  cas IPv4 extended sans ports. Les ACE complexes donnent UNKNOWN si aucune
  règle masquée n'a été démontrée.
- Les contrôles de passerelle indiquent un next-hop non directement connecté,
  mais ne prouvent pas une panne (routes récursives possibles).
- Aucun test dynamique n'est réalisé sur les équipements.
- Ne pas publier des configurations, sorties de rapports ou secrets réels.

## Validation de ce paquet

- 8 tests ciblés : OK.
- Référence CIS : 117/117, 0 anomalie (sur la copie de validation disponible).
- Test complet de la suite et rendu PDF end-to-end : à **rejouer dans le WSL**
  de l'utilisateur ; notre copie de travail manque de fixtures et Flask.
