# 6NLG — Benchmark étendu de parsing / IR par famille

## Contenu

- `configs/` : 50 configurations synthétiques IOS 15, 5 par famille.
- `gold/` : 50 références de faits sémantiques définies par les scénarios, **pas à partir de la sortie du parseur**.
- `export/parsing/` : 50 JSON de parsing complets.
- `export/ir/` : 50 JSON de normalisation IR complets.
- `summary.json` : métriques par famille et étape.
- `details.json` : erreurs par scénario, faits manqués et faits ajoutés.
- `build.py` : génération reproductible des cas et des références.
- `evaluate_export.py` : comparaison et export des JSON.

## Résultat sur V6.7 corrigé

Pour les **180 faits sémantiques ciblés** dans ces 50 scénarios, précision, rappel et F1 = 100 % pour le parsing ET pour l'IR. Chaque famille a 5 scénarios avec des valeurs différentes. Ce chiffre ne certifie PAS toutes les commandes ou les options du domaine.

Les comparaisons portent sur des faits sélectionnés (identifiants, routes, réseaux, noms, nombres de règles, etc.). Elles ne couvrent pas toute la structure JSON, ni tous les mots-clés d'une commande. Par exemple, `no auto-summary` sous EIGRP est compté dans une zone non modélisée de ce parseur ; le mot-clé `log` d'une ACL peut être conservé comme jeton non modélisé dans l'IR. Un score de 100 % ici ne prouve pas leur prise en charge.

## Exécution Ubuntu

```bash
cd ~/projet-6nlg/network-config-audit
source .venv/bin/activate
python3 benchmark_50_6nlg/evaluate_export.py --project .
```

## Limites scientifiques et prochaine étape

Le corpus est **synthétique, construit par familles avec cinq variantes paramétriques proches**, sans annotation indépendante de configurations réelles. Il sert de test de régression et de couverture fonctionnelle de base.

Pour une mesure de fiabilité externe : constituer des configurations indépendantes, annoter les champs et options complets par des évaluateurs humains, tester les syntaxes alternatives et les cas erronés, et calculer une matrice par commande/champ. Ne pas confondre ces 180 faits avec le périmètre total de Cisco IOS 15 ou les 39 contrôles CIS.
