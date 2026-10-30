# 6NLG — IR v2.1 : extension multiconstructeur et fonctions Juniper Junos

Version : 28 octobre 2026. Correctif **additif** pour le projet existant
`~/projet-6nlg/network-config-audit`. Il n'installe ni ne réécrit le parseur
Cisco et ne modifie pas `normalizers/juniper_ir_adapter.py` (IR v1).

## 1. Fonctionnement

1. `CiscoConfParse(syntax="junos", factory=False)` construit la hiérarchie
   depuis un fichier de configuration Junos à accolades.
2. `normalizers/juniper_ir_adapter.py` produit l'IR v1 existante.
3. `normalizers/policy_ir_v2.py` conserve l'IR v1 et ajoute la représentation
   des politiques de routage (`route_policies`, `community_sets`).
4. `normalizers/juniper_features_ir_v2.py` enrichit l'IR dans un champ
   **optionnel** `junos_details` : BGP, OSPF, IS-IS, MPLS, LDP, RSVP, EVPN,
   LLDP, interfaces, VRF, options de commutation, sécurité et forwarding.
5. `schemas/network_device_ir_v2.schema.json` valide explicitement les types
   de ces champs. Les fichiers Cisco IR v2 conservent leurs propres sémantiques
   et n'ont pas besoin du champ `junos_details`.

## 2. Fonctionnalités modélisées

| Famille | Exemples de champs **configurés** (pas d'état opérationnel) |
|---|---|
| BGP | BFD, intervalle et multiplicateur, modes de session, multipath, `multiple-as`, MTU discovery, politiques import/export ordonnées, `cluster`, préférence, graceful restart |
| OSPF | Aires, interfaces, passive, BFD, présence de MD5 avec secret masqué, bande passante de référence, traffic-engineering |
| IS-IS | Interfaces, passive et niveaux explicitement désactivés |
| MPLS | Interfaces, mode traffic-engineering, LSP et destination, fast reroute, tunneling IPv6, `record` |
| LDP/RSVP | Interfaces et `make-before-break` pour LDP |
| EVPN | Encapsulation, option default-gateway, extended-vni-list |
| LLDP | Interfaces, sous-type de Port ID |
| Interfaces | IPv6, VLAN trunk, membres VLAN, family MPLS, passerelles virtuelles IRB |
| VRF | Import/export policy, multipath, auto-export, IRB EVPN, VNI et routes de préfixe |
| Sécurité/commutation | Familles forwarding en mode packet/flow, VTEP, RT/RD, storm-control et forwarding-table |
| Routing policy | Route-filter exact/orlonger/longer/prefix-length-range, communautés, next-hop, AS-path prepend, next term/policy, load balance |

Les champs booléens suffixés `_configured` sont **présents uniquement**
lorsque la directive correspondante a été identifiée. Son absence n'indique
pas que la fonction est désactivée.

**Limites importantes** :

- IR v2 conforme au JSON Schema ≠ comportement réseau correct.
- Pour les interfaces et protocoles, les compteurs de cette extension sont
  indépendants de la couverture déjà produite par l'IR v1. **Ne pas les
  additionner** : un même élément peut être couvert par les deux projections.
- Des commandes non normalisées subsistent, y compris dans les corpus testés.
  Aucune commande inconnue n'est déclarée valide ou fonctionnelle par défaut.
- Les descriptions libres, mots de passe, clés et commandes brutes ne sont
  pas recopiés dans les nouveaux champs JSON. L'authentification OSPF est
  résumée par `secret_redacted: true`.
- Les fichiers Junos `show configuration | display set` à plat (dont le SRX
  actuellement fourni) ne sont **pas encore pris en charge** par cet adaptateur.
- Les configurations de développement ne constituent pas un holdout aveugle.
  Les 3 configurations Batfish additionnelles vérifient la robustesse
  structurelle, mais il faut une vérité terrain indépendante pour mesurer
  l'exactitude de chaque champ.

## 3. Installation dans le projet WSL **existant**

Vérifier les fichiers du ZIP :

```bash
cd ~/projet-6nlg/network-config-audit
unzip -l "/mnt/c/Users/LENOVO/Downloads/6NLG_IR_V2_1_MULTI_FONCTIONS.zip"
```

Faire des copies **avant** la mise à jour des trois fichiers partagés :

```bash
mkdir -p .backup-ir-v2_1
cp normalizers/policy_ir_v2.py .backup-ir-v2_1/
cp scripts/evaluate_ir_v2_policies.py .backup-ir-v2_1/
cp schemas/network_device_ir_v2.schema.json .backup-ir-v2_1/
```

Extraire le correctif (ici `-o` est voulu pour les trois fichiers existants) :

```bash
unzip -o "/mnt/c/Users/LENOVO/Downloads/6NLG_IR_V2_1_MULTI_FONCTIONS.zip" -d .
source .venv/bin/activate
python3 -m pip install -r requirements-juniper.txt
```

L'archive ne contient aucun fichier `normalizers/cisco_normalizer.py`,
`parsers/cisco_parser.py` ou `webapp/app.py`.

## 4. Tests complets

```bash
PYTHONPATH=parsers python3 -m unittest discover \
  -s tests -p 'test_*.py' -v
```

Validation du corpus Junos initial :

```bash
PYTHONPATH=parsers python3 scripts/evaluate_ir_v2_policies.py \
  --junos ../juniper_sources/batfish-lab-validation/snapshots/junos_evpn_type5/source/configs \
          ../juniper_sources/junosphere \
  --schema schemas/network_device_ir_v2.schema.json \
  --output-dir reports/ir_v2_1/juniper \
  --json-summary reports/validation_ir_v2_1_juniper.json \
  --strict-schema
```

Validation additionnelle sur **trois fichiers d'autres scénarios Batfish** :

```bash
PYTHONPATH=parsers python3 scripts/evaluate_ir_v2_policies.py \
  --junos \
  ../juniper_sources/batfish-lab-validation/snapshots/junos_bgp_socket_buffers/source/configs/dut.cfg \
  ../juniper_sources/batfish-lab-validation/snapshots/junos_route_communities/source/configs/sender.cfg \
  ../juniper_sources/batfish-lab-validation/snapshots/junos_ospf_topology_metric/source/configs/dut.cfg \
  --schema schemas/network_device_ir_v2.schema.json \
  --output-dir reports/ir_v2_1/holdout \
  --json-summary reports/validation_ir_v2_1_holdout.json \
  --strict-schema
```

Régression Cisco sur les trois cas synthétiques **si présents** :

```bash
PYTHONPATH=parsers python3 scripts/evaluate_ir_v2_policies.py \
  --cisco data/holdout_synthetique_v66 \
  --schema schemas/network_device_ir_v2.schema.json \
  --output-dir reports/ir_v2_1/cisco \
  --json-summary reports/validation_ir_v2_1_cisco.json \
  --strict-schema
```

**Important** : les tests doivent afficher des résultats ; le script refuse
désormais explicitement les chemins inexistants et les corpus vides.

## 5. Bilan de référence, sans généralisation

Mesures réalisées sur une copie locale des fichiers publics le 28/10/2026 :

| Jeu | Schéma IR v2 | Note |
|---|---|---|
| 6 Batfish EVPN + 18 Junosphere | 24/24 | toujours `schema_valid_partial` |
| 3 nouveaux scénarios Batfish | 3/3 | normalisation partielle, davantage de variantes non reconnues |
| 3 configurations Cisco synthétiques | 3/3 | IR Cisco inchangée et compatible v2 |

Dans les 24 Junos connus :

- `policy-options` : **300/303 feuilles** reconnues dans la projection des
  politiques v2 (3 non modélisées).
- `protocols` : **267/410 feuilles** reconnues par la **nouvelle projection
  fonctionnelle**. Les 143 autres ne sont *pas nécessairement inconnues à
  l'IR v1* : cet indicateur ne mesure pas la couverture combinée.
- `security` : 54/54, `switch-options` : 9/9 et `forwarding-options` : 3/3
  sur les **formes observées**. Cela ne signifie pas que tout Junos Security
  ou toute la gamme Juniper sont pris en charge.

Le document `reports/NOTE_RESULTATS_IR_V2_1.md` donne les détails et
les décisions techniques restantes.

## 6. Étapes à poursuivre avant le moteur d'audit

1. Mesurer l'union dédupliquée des couvertures v1 et v2 sur chaque source.
2. Étudier les feuilles restantes de façon *contextuelle* (famille, variante,
   validité et sens documenté), sans les classer automatiquement en « OK ».
3. Ajouter une bibliothèque d'import `display set` Junos avant le SRX.
4. Construire un jeu **indépendant** de configurations annotées (oracle),
   y compris configurations invalides, VRF/BGP/OSPF complexes et variantes.
5. Étendre les routes IPv6, redistribution et les politiques de firewall avec
   des schémas dédiés et des validations sémantiques.
6. Intégrer la sélection Cisco / Juniper et les résultats IR v2 dans Flask,
   après le raccordement de l'adaptateur à l'interface existante.

## Documentation fournisseur utilisée pour les règles explicites

- Juniper BFD : https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/minimum-interval-edit-protocols-bgp-liveness-detection.html
- Juniper EVPN : https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/enapsulation-vxlan-edit-routing-instances.html
- Juniper IS-IS : https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/interface-edit-protocols-isis.html
- Juniper route-filter : https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/concept/routing-policy-security-route-based-match-condition-understanding.html
- Juniper actions de politiques : https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/concept/policy-configuring-actions-in-routing-policy-terms.html
