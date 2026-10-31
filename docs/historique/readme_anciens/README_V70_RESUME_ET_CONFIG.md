# 6NLG V70 — Résumé des erreurs et aperçu de configuration

Ce correctif est cumulatif à V69 : **installer V69 avant V70**.

## Fonctionnalités

1. Après import Cisco IOS, bouton **Résumé des FAIL (CSV)** : colonnes
   `Contrôle CIS / Règle / Erreur / Impact / Emplacement / Correction / Vérification`.
   Inclut uniquement les contrôles CIS `FAIL`, puis les diagnostics réseau
   `FAIL` et `REVIEW` (étiquetés `RESEAU`). Les contrôles `UNKNOWN` ne sont
   pas considérés non conformes sans preuve.
2. Bouton **Voir configuration importée** : ouvre la section correspondante
   du rapport CIS HTML. Les lignes sont numérotées ; secrets, bannières,
   descriptions, commentaires et directives ambiguës sont masqués.
3. Le rapport HTML exporté contient la vue expurgée et le résumé des FAIL.
   Le rapport PDF existant garde ses sections détaillées CIS.
4. Dossier `benchmark_cis39_holdout/` : deux configurations supplémentaires
   avec oracle explicite sur 78 verdicts CIS et 8 diagnostics réseau.

## Installation WSL2

Depuis la racine `~/projet-6nlg/network-config-audit`, créer une branche
ou sauvegarder les changements avant d'extraire.

```bash
unzip -l /mnt/c/Users/LENOVO/Downloads/6NLG_CORRECTIF_V70_RESUME_CONFIG.zip
unzip -o /mnt/c/Users/LENOVO/Downloads/6NLG_CORRECTIF_V70_RESUME_CONFIG.zip
PYTHONPATH=.:parsers:final_validation_6nlg python3 -m unittest tests.test_cis_export_features -v
PYTHONPATH=.:parsers:final_validation_6nlg python3 -m unittest tests.test_cis39_holdout -v
python3 validation_reference_cis_39/run_validation.py .
python3 -m webapp
```

Importer une configuration Cisco, choisir profil L2 et configuration complète
si justifié, puis tester les deux nouveaux liens dans l'étape CIS.

## Sécurité / limites

- Aucun fichier brut n'est conservé : seul un aperçu expurgé est stocké
  temporairement en mémoire dans le rapport HTML, soumis à la session.
- La liste blanche de l'aperçu est volontairement conservatrice. Certaines
  directives pourtant légitimes apparaîtront comme non affichées ; consulter
  l'original local pour leur syntaxe complète.
- Le CSV est un diagnostic statique et non un correctif automatique.
- Les tests automatisés vérifient les exports et la non-divulgation ; la suite
  Flask complète doit être lancée dans l'environnement WSL avec Flask installé.
- Le benchmark A/B teste 78 verdicts attendus mais ne constitue pas encore une
  matrice complète de trois cas indépendants pour chacun des 39 contrôles.
