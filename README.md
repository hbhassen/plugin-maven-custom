# plugin-maven-custom
Spécification détaillée – Maven Plugin xray-scan
1. Contexte et objectif

Le plugin Maven xray-scan a pour but d’automatiser le scan de vulnérabilités d’un projet Java à l’aide de l’API JFrog Xray.
Il doit :

S’intégrer nativement au cycle Maven (compatible Maven 3.8+).

Être configurable via le pom.xml ou en ligne de commande Maven (-Dproperties).

Appeler l’API REST de JFrog Xray pour analyser le projet selon un Watch (politique de seuil) donné.

Retourner la liste des CVE détectées.

Échouer (BUILD FAILURE) si au moins une vulnérabilité dépasse le score seuil configuré par le Watch.

Réussir (BUILD SUCCESS) si aucune CVE n’a un score ≥ seuil.

Le plugin inclut un Watch par défaut avec un score seuil de 7.0 (CVSS ≥ 7 → échec).
L’utilisateur peut surcharger ce Watch par défaut en fournissant un custom watch au moment de l’exécution Maven.

2. Compatibilité

Maven : 3.8.x et +

Java : 17 et +

Compatible avec des projets Maven Java / Java-Spring / JEE.

Testé avec JFrog Xray 3.x+ (API v2 REST).

3. Paramètres de configuration
3.1. Dans le pom.xml
<build>
  <plugins>
    <plugin>
      <groupId>com.mycompany</groupId>
      <artifactId>xray-scan-maven-plugin</artifactId>
      <version>1.0.0</version>
      <configuration>
        <xrayUrl>https://my-jfrog-xray-instance/api/v2</xrayUrl>
        <username>myUser</username>
        <password>${env.XRAY_PASSWORD}</password>
        <watch>default</watch> <!-- optionnel, sinon “default” -->
        <failOnThreshold>true</failOnThreshold>
      </configuration>
    </plugin>
  </plugins>
</build>

3.2. En ligne de commande Maven
mvn com.mycompany:xray-scan-maven-plugin:1.0.0:scan \
  -DxrayUrl=https://xray.mycompany.com/api/v2 \
  -Dusername=john.doe \
  -Dpassword=secret123 \
  -Dwatch=critical-watch


Note : si watch n’est pas fourni → le plugin utilise le Watch par défaut (scoreSeuil=7).

4. Paramètres acceptés
Nom du paramètre	Type	Obligatoire	Valeur par défaut	Description
xrayUrl	String	Oui	–	URL de l’API REST de JFrog Xray (…/api/v2).
username	String	Oui	–	Nom d’utilisateur JFrog Xray.
password	String	Oui	–	Mot de passe ou token API de l’utilisateur.
watch	String	Non	default	Nom du Watch à utiliser pour le scan.
failOnThreshold	Boolean	Non	true	Si true, le build échoue si CVE ≥ seuil.
timeoutSeconds	Integer	Non	300	Timeout max pour l’attente des résultats du scan.
5. Objectif Maven et phase

Nom de l’objectif : scan

Par défaut bindé à la phase : verify

Exemple : mvn xray-scan:scan ou automatique à la phase verify si déclaré.

6. Flux fonctionnel du plugin

Lecture des paramètres (pom ou CLI).

Validation : vérifier que xrayUrl, username, password sont définis.

Connexion à JFrog Xray (API REST v2) en utilisant Basic Auth (ou Token si fourni).

Création du rapport de scan via l’API /scan/ ou /summary/artifact selon le mode.

Récupération de la liste des vulnérabilités détectées pour le projet.

Filtrage des vulnérabilités selon le score seuil du Watch choisi.

Affichage dans la console Maven d’un tableau des CVE détectées :

CVE-ID

Paquet concerné

Version

Score CVSS

Description courte

Retour d’exécution :

Si aucune CVE ≥ seuil : BUILD SUCCESS

Si ≥ 1 CVE ≥ seuil et failOnThreshold=true : BUILD FAILURE + sortie code 1

Le plugin génère un rapport JSON dans :

target/xray-scan-report.json

7. Structure de réponse JSON attendue

Exemple d’objet attendu depuis l’API JFrog Xray :

{
  "summary": {
    "total_artifacts": 25,
    "total_violations": 3
  },
  "violations": [
    {
      "issue_id": "CVE-2024-1234",
      "package_name": "log4j-core",
      "package_version": "2.17.0",
      "cvss_score": 9.8,
      "severity": "Critical",
      "summary": "Remote code execution vulnerability"
    }
  ]
}


Le plugin parse cette structure et conserve uniquement les violations.

8. Comportement d’erreur

401 / 403 : mauvais credentials → MojoFailureException.

404 Watch introuvable → erreur claire.

Timeout : erreur avec code non zéro.

Problème réseau : échec du build sauf si paramètre failOnThreshold=false.

9. Sécurité

Le mot de passe ne doit jamais apparaître dans les logs Maven.

Support de variables d’environnement ou du settings.xml Maven pour sécuriser le mot de passe.

10. Structure du projet plugin
xray-scan-maven-plugin/
 ├─ pom.xml
 ├─ src/main/java/com/mycompany/xrayscan/
 │    ├─ XrayScanMojo.java           (Mojo principal)
 │    ├─ XrayClient.java             (appel API REST)
 │    ├─ model/CveResult.java        (POJO)
 │    └─ utils/ReportWriter.java     (JSON → fichier)
 └─ src/main/resources/META-INF/maven/
      └─ plugin.xml                  (déclaration plugin)

11. Classes principales

XrayScanMojo

Annoté avec @Mojo(name="scan", defaultPhase=LifecyclePhase.VERIFY).

Lit les paramètres via @Parameter.

Exécute le flux fonctionnel.

XrayClient

Gère l’authentification et les appels REST (via HttpClient ou WebClient).

CveResult

Contient : cveId, packageName, version, cvssScore, severity, summary.

ReportWriter

Sérialise la liste des vulnérabilités au format JSON vers target/xray-scan-report.json.

12. Exemple d’exécution
mvn verify
[INFO] --- xray-scan-maven-plugin:1.0.0:scan ---
[INFO] Connecting to https://xray.mycompany.com/api/v2 ...
[INFO] Using watch: critical-watch (threshold=8)
[INFO] Found 2 vulnerabilities above threshold:
CVE-2024-1234 | log4j-core | 2.17.0 | CVSS=9.8 | Critical
CVE-2023-4321 | commons-io | 2.6    | CVSS=8.5 | High
[ERROR] Build failed due to vulnerabilities exceeding threshold
[INFO] BUILD FAILURE

13. Rapport attendu

Fichier : target/xray-scan-report.json
Contenu : liste complète des vulnérabilités trouvées, y compris celles sous le seuil.

14. Tests unitaires

Mock du client HTTP (via WireMock).

Cas de succès, cas d’échec (CVE ≥ seuil), credentials invalides, timeout.

15. Livrables attendus

Code source complet Maven Plugin (pom.xml, classes Java, plugin.xml).

README.md expliquant :

Installation

Configuration (pom.xml, CLI)

Exemples d’exécution

Gestion des erreurs

Fichier LICENSE (Apache 2.0).

Tests unitaires dans src/test/java.

16. Critères d’acceptation

Compatible Maven ≥ 3.8

Fonctionne avec JDK 17

Paramètres configurables pom/CLI

Retourne BUILD FAILURE si CVE ≥ seuil

Rapports clairs en console et fichier JSON

Code commenté et testé (≥ 80 % couverture).

✅ Ce document peut être directement donné à un agent génératif (Codex) pour produire le code source complet du plugin et la documentation associée (README.md).

Sources / Références :

JFrog Xray REST API v2 – Scanning

Maven Plugin Development – Apache Maven Docs

Mojo Annotations – org.apache.maven.plugins.annotations

CVSS v3.1 Scoring – FIRST.org
