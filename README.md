# xray-scan-maven-plugin

Plugin Maven permettant d'automatiser le contrôle de vulnérabilités d'un projet Java via un **Watch** JFrog Xray. Il s'intègre dans le cycle Maven (phase `verify`) afin de bloquer l'installation/deployment d'un artefact lorsque le watch signale une CVE critique.

## 1. Fonctionnalités principales

- Connexion à JFrog Xray (API REST v2) et interrogation du watch configuré via l'endpoint `GET /api/v2/violations`.
- Récupération du seuil CVSS défini par le watch (ou seuil par défaut `7.0` s'il n'est pas exposé) afin de déterminer les vulnérabilités bloquantes.
- Prise en compte uniquement des dépendances en portée `compile` (y compris l'artefact principal) pour éviter les faux positifs.
- Génération d'un rapport JSON (`target/xray-scan-report.json`) listant toutes les vulnérabilités retournées par le watch, dans la même structure que précédemment.
- Échec du build (`MojoFailureException`) dès qu'une CVE dépasse le seuil du watch lorsque `failOnThreshold=true` (par défaut).
- Possibilité de continuer le build pour des usages exploratoires en positionnant `-DfailOnThreshold=false`.
- Watch par défaut (`default`) surchargeable via la configuration Maven ou la ligne de commande (`-Dwatch=...`).

## 2. Prérequis

| Outil                | Version minimale |
|----------------------|------------------|
| Maven                | 3.8.x            |
| Java                 | 17               |
| JFrog Xray           | 3.x (API REST v2)|

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
        <watch>default</watch>
        <failOnThreshold>true</failOnThreshold>
        <timeoutSeconds>300</timeoutSeconds>
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

| Propriété         | Type    | Défaut    | Description |
|-------------------|---------|-----------|-------------|
| `xrayUrl`         | String  | –         | URL de base de l'API JFrog Xray (terminée par `/api/v2`). |
| `username`        | String  | –         | Identifiant ou access token (non loggé). |
| `password`        | String  | –         | Mot de passe ou token API (peut provenir d'une variable d'environnement ou du `settings.xml`). |
| `watch`           | String  | `default` | Nom du watch Xray à interroger. |
| `failOnThreshold` | Boolean | `true`    | Si `true`, le build échoue lorsqu'une violation dépasse le seuil défini par le watch. |
| `timeoutSeconds`  | Integer | `300`     | Timeout maximal pour chaque appel HTTP. |
| `skip`            | Boolean | `false`   | Permet d'ignorer totalement le scan (ex : intégration locale sans Xray). |

### 4.3 Exécution via la ligne de commande

```bash
mvn com.mycompany:xray-scan-maven-plugin:1.0.0:scan \
  -DxrayUrl=https://xray.mycompany.com/api/v2 \
  -Dusername=john.doe \
  -Dpassword=${XRAY_TOKEN} \
  -Dwatch=critical-services \
  -DfailOnThreshold=true
```

## 5. Résultats et rapport

- Les vulnérabilités sont listées dans les logs Maven sous la forme :
  `CVE-ID | package | version | fixed-version | CVSS | severity`.
- Le rapport JSON (`target/xray-scan-report.json`) contient l'intégralité des violations remontées par le watch, même celles en dessous du seuil :

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

## 6. Comportement du build

| Cas                                    | Comportement |
|----------------------------------------|--------------|
| Au moins une CVE ≥ seuil du watch      | `MojoFailureException` → `BUILD FAILURE`. |
| Aucune CVE ≥ seuil du watch            | `BUILD SUCCESS` (log des vulnérabilités détectées sous le seuil). |
| `failOnThreshold=false`                | Le build continue (`BUILD SUCCESS`) mais un warning est affiché. |
| 401 / 403                              | `MojoFailureException` – identifiants invalides. |
| Timeout ou erreur réseau               | `MojoExecutionException`. |

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

- Code Java 17, annotations `@Mojo` fournies par `maven-plugin-annotations`.
- Client HTTP basé sur `java.net.http` avec gestion du timeout et des codes d'erreur.
- Tests unitaires utilisant WireMock pour simuler l'API Xray (succès, dépassement de seuil, authentification invalide, dépendances filtrées).

## 8. Licence

Ce projet est distribué sous licence [Apache 2.0](LICENSE).

## 9. Références

- [JFrog Xray REST API v2](https://www.jfrog.com/confluence/display/JFROG/Xray+REST+API)
- [Watches Xray](https://jfrog.com/help/r/jfrog-xray-documentation/working-with-watches)
- [Développement de plugins Maven](https://maven.apache.org/guides/plugin/guide-java-plugin-development.html)
- [Documentation CVSS v3.1](https://www.first.org/cvss/)
