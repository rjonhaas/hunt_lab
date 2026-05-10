# ATT&CK Navigator layers

Layer JSON files exported for [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
Each one highlights the techniques exercised by a specific lab scenario.

## Available layers

| File                          | Scenario                                                                                |
|-------------------------------|-----------------------------------------------------------------------------------------|
| `ransomhub_layer.json`        | DFIR-RansomHub-2025-Lab — full chain (12 attack abilities + 3 dwell)                    |
| `identity_chain_layer.json`   | Identity-Chain-2025-Lab — Kerberoast → DCSync → Golden Ticket → PtT (6 attack + 2 dwell) |

## How to view

1. Open <https://mitre-attack.github.io/attack-navigator/>.
2. **Open Existing Layer → Upload from local** → select the JSON file.
3. Optionally export the rendered matrix as SVG/PNG via the camera icon.

The layer files are static — if you change the Caldera adversary chain, update
the corresponding `*_layer.json` and refresh the screenshot in the project
README.
