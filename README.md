# xray-scan-maven-plugin

Plugin Maven permettant d'automatiser le scan de vulnérabilités d'un projet Java via l'API "On-Demand Binary Scan" de JFrog Xray (`api/v1/scan/graph`). Il se base sur la spécification fournie et fournit un objectif `scan` rattaché par défaut à la phase `verify`.

## 1. Fonctionnalités principales

- Connexion à JFrog Xray (authentification Basic) et déclenchement d'un scan à la demande sur le graphe de dépendances (`api/v1/scan/graph`).
- Seuil CVSS configurable (`threshold`, défaut 7.0) appliqué localement lors de l'analyse des résultats.
- Génération d'un rapport JSON complet dans `target/xray-scan-report.json`.
- Affichage dans la console Maven des CVE détectées triées par score décroissant.
- Échec du build (`MojoFailureException`) si au moins une vulnérabilité dépasse le seuil et que `failOnThreshold=true`.
- Possibilité de continuer le build en mode dégradé (`failOnThreshold=false`).

## 2. Prérequis

| Outil                | Version minimale |
|----------------------|------------------|
| Maven                | 3.8.x            |
| Java                 | 17               |
| JFrog Xray           | 3.x (API REST v1/v2)|

## 3. Installation

Publiez le plugin dans votre repository Maven interne, ou installez-le localement :

```bash
mvn clean install
```

## 4. Configuration dans un projet Maven

### 4.1 Déclaration dans le `pom.xml`

```xml
<build>
  <plugins>
    <plugin>
      <groupId>com.mycompany</groupId>
      <artifactId>xray-scan-maven-plugin</artifactId>
      <version>1.0.0</version>
      <configuration>
        <xrayUrl>https://mon-xray/api/v2</xrayUrl>
        <username>monUser</username>
        <password>${env.XRAY_PASSWORD}</password>
        <failOnThreshold>true</failOnThreshold>
        <timeoutSeconds>300</timeoutSeconds>
        <threshold>7.0</threshold>
      </configuration>
      <executions>
        <execution>
          <goals>
            <goal>scan</goal>
          </goals>
        </execution>
      </executions>
    </plugin>
  </plugins>
</build>
```

### 4.2 Paramètres disponibles

| Propriété         | Type    | Défaut  | Description |
|-------------------|---------|---------|-------------|
| `xrayUrl`         | String  | –       | URL de base de l'API JFrog Xray (terminée par `/api/v2`, le plugin utilise automatiquement `api/v1/scan/graph`). |
| `username`        | String  | –       | Identifiant ou access token (le mot de passe ne sera pas loggé). |
| `password`        | String  | –       | Mot de passe ou token API. Peut provenir d'une variable d'environnement ou du `settings.xml`. |
| `failOnThreshold` | Boolean | `true`  | Si `true`, le build échoue lorsqu'une violation dépasse le seuil. |
| `timeoutSeconds`  | Integer | `300`   | Timeout maximal pour chaque appel HTTP. |
| `threshold`       | Double  | `7.0`   | Seuil CVSS appliqué localement (>= déclenche l'échec si `failOnThreshold=true`). |
| `skip`            | Boolean | `false` | Permet d'ignorer totalement le scan. |

### 4.3 Exécution via la ligne de commande

```bash
mvn com.mycompany:xray-scan-maven-plugin:1.0.0:scan \
  -DxrayUrl=https://xray.mycompany.com/api/v2 \
  -Dusername=john.doe \
  -Dpassword=${XRAY_TOKEN} \
  -Dthreshold=8.0 \
  -DfailOnThreshold=true
```

## 5. Résultats et rapport

- Les vulnérabilités sont listées dans les logs Maven sous la forme :
  `CVE-ID | package | version | CVSS | severity | fixed-version`.
- Le rapport JSON (`target/xray-scan-report.json`) contient l'intégralité des violations (y compris celles sous le seuil) :

```json
[
  {
    "cveId": "CVE-2024-1234",
    "packageName": "log4j-core",
    "version": "2.17.0",
    "cvssScore": 9.8,
    "severity": "Critical",
    "summary": "Remote code execution vulnerability",
    "fixedVersion": "2.17.1"
  }
]
```

## 6. Gestion des erreurs

| Cas                        | Comportement |
|---------------------------|--------------|
| 401 / 403                 | `MojoFailureException` – identifiants invalides. |
| Timeout ou erreur réseau  | `MojoExecutionException`. |
| `failOnThreshold=false`   | Le build continue, avec un warning si des vulnérabilités dépassent le seuil. |

Le mot de passe n'est jamais loggé. Pensez à utiliser les variables d'environnement, le `settings.xml` ou un vault.

## 7. Développement

### 7.1 Structure du projet

```
xray-scan-maven-plugin/
 ├─ pom.xml
 ├─ src/main/java/com/mycompany/xrayscan/
 │    ├─ XrayScanMojo.java
 │    ├─ XrayClient.java
 │    ├─ model/CveResult.java
 │    └─ utils/ReportWriter.java
 ├─ src/test/java/com/mycompany/xrayscan/
 │    └─ XrayScanMojoTest.java
 └─ target/
```

### 7.2 Lancer les tests

```bash
mvn clean test
```

### 7.3 Qualité et bonnes pratiques

- Couverture de test ciblant les scénarios principaux : succès, dépassement de seuil, authentification invalide.
- Code Java 17, annotations `@Mojo` fournies par `maven-plugin-annotations`.
- HTTP client natif (`java.net.http`) avec gestion du timeout et des codes d'erreur.

## 8. Licence

Ce projet est distribué sous licence [Apache 2.0](LICENSE).

## 9. Références

- [JFrog Xray REST API v2](https://www.jfrog.com/confluence/display/JFROG/Xray+REST+API)
- [Xray On-Demand Binary Scan](https://jfrog.com/help/r/xray-jf-docker-scan-watches-xx-with-ignore-rule/xray-on-demand-binary-scan)
- [Développement de plugins Maven](https://maven.apache.org/guides/plugin/guide-java-plugin-development.html)
- [Documentation CVSS v3.1](https://www.first.org/cvss/)
