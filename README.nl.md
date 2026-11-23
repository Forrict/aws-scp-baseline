# AWS SCP-basisset

Tien service control policies (SCP's) die wij bij [Forrict](https://www.forrict.nl/nl/) gebruiken als startpunt voor een AWS Organization. Bij elke push worden alle policies automatisch gecontroleerd: JSON-structuur, de maximale grootte van een SCP, en elke actie en condition key tegen de officiële AWS Service Authorization Reference.

De volledige uitleg per policy staat in de Engelstalige [README](README.md) en in de blog [10 SCP's die elke AWS-organisatie nodig heeft](https://www.forrict.nl/nl/blog/).

**Eerst testen.** Een SCP kan werk blokkeren in elk account onder de OU waar je hem aan hangt. Hang ze eerst aan een test-OU, kijk in CloudTrail naar `AccessDenied`-fouten en rol daarna OU voor OU uit. SCP's gelden nooit voor het management account.

## Wat je vooraf aanpast

- **Uitzonderingsrol.** Policies 3 tot en met 10 gelden niet voor `AWSControlTowerExecution` (de rol van AWS Control Tower) en `GuardrailAdmin`. Die tweede naam is een voorbeeld: vervang hem door je eigen beheerrol.
- **Regio's.** Policy 3 staat alleen `eu-central-1` (Frankfurt) en `eu-west-1` (Ierland) toe. Pas de lijst aan voordat je hem koppelt; resources in andere regio's zijn daarna niet meer bereikbaar. Gebruik je Control Tower, zet dan de ingebouwde Region deny-control aan in plaats van deze policy.
- **Maximaal 10 per doel.** Je kunt maximaal 10 SCP's direct aan de root, een OU of een account hangen, inclusief `FullAWSAccess`. Voeg dus een paar policies samen, of verdeel ze over root en OU's.

## Zelf controleren

```bash
python3 scripts/validate.py
python3 -m unittest discover -s tests -v
```

Met AWS-credentials kun je ook IAM Access Analyzer laten meekijken: `scripts/validate-with-access-analyzer.sh`. Dat leest alleen de policytekst en wijzigt niets in je account.

## Licentie

MIT-0. Een deel van de policies is gebaseerd op de [voorbeelden van AWS zelf](https://github.com/aws-samples/service-control-policy-examples) (ook MIT-0). Zonder garantie: test ze in je eigen omgeving.
