package com.mycompany.xrayscan;

import com.mycompany.xrayscan.model.CveResult;
import com.mycompany.xrayscan.utils.ReportWriter;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.OptionalDouble;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Mojo principal déclenchant le scan JFrog Xray.
 */
@Mojo(name = "scan", defaultPhase = LifecyclePhase.VERIFY, threadSafe = true)
public class XrayScanMojo extends AbstractMojo {

    private static final double DEFAULT_THRESHOLD = 7.0d;

    @Parameter(property = "xrayUrl", required = true)
    private String xrayUrl;

    @Parameter(property = "username", required = true)
    private String username;

    @Parameter(property = "password", required = true)
    private String password;

    @Parameter(property = "watch", defaultValue = "default")
    private String watch;

    @Parameter(property = "failOnThreshold", defaultValue = "true")
    private boolean failOnThreshold;

    @Parameter(property = "timeoutSeconds", defaultValue = "300")
    private int timeoutSeconds;

    @Parameter(defaultValue = "${project}", readonly = true)
    private MavenProject project;

    @Parameter(property = "skip", defaultValue = "false")
    private boolean skip;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            getLog().info("Scan JFrog Xray ignoré (skip=true)");
            return;
        }

        validateParameters();

        Duration timeout = Duration.ofSeconds(Math.max(timeoutSeconds, 1));
        try {
            XrayClient client = new XrayClient(xrayUrl, username, password, timeout, getLog());
            double threshold = resolveThreshold(client);
            getLog().info(String.format(Locale.ROOT, "Utilisation du watch '%s' (seuil=%.1f)", watch, threshold));

            List<CveResult> violations = client.fetchViolations(watch);
            List<CveResult> filteredViolations = filterViolationsByCompileScope(violations);
            List<CveResult> sorted = new ArrayList<>(filteredViolations);
            sorted.sort(Comparator.comparingDouble(CveResult::getCvssScore).reversed());

            Path reportPath = getReportPath();
            new ReportWriter().write(reportPath, sorted);
            getLog().info("Rapport JSON généré dans " + reportPath);

            List<CveResult> aboveThreshold = sorted.stream()
                    .filter(v -> v.getCvssScore() >= threshold)
                    .collect(Collectors.toList());

            if (aboveThreshold.isEmpty()) {
                if (sorted.isEmpty()) {
                    getLog().info("Aucune vulnérabilité détectée par Xray.");
                } else {
                    getLog().info("Aucune vulnérabilité ne dépasse le seuil configuré.");
                }
                logViolations(sorted);
                return;
            }

            getLog().error(String.format(Locale.ROOT,
                    "%d vulnérabilité(s) dépassent le seuil CVSS %.1f :", aboveThreshold.size(), threshold));
            logViolations(aboveThreshold);

            if (failOnThreshold) {
                throw new MojoFailureException("Scan Xray échoué : vulnérabilité(s) critique(s) détectée(s).");
            } else {
                getLog().warn("Des vulnérabilités dépassent le seuil mais failOnThreshold=false");
            }
        } catch (XrayClient.AuthenticationException e) {
            throw new MojoFailureException("Authentification Xray échouée : " + e.getMessage(), e);
        } catch (XrayClient.WatchNotFoundException e) {
            throw new MojoFailureException("Watch introuvable : " + watch, e);
        } catch (IOException e) {
            throw new MojoExecutionException("Erreur d'appel à l'API JFrog Xray", e);
        }
    }

    private void validateParameters() throws MojoExecutionException {
        if (isBlank(xrayUrl)) {
            throw new MojoExecutionException("Le paramètre xrayUrl est obligatoire");
        }
        if (isBlank(username)) {
            throw new MojoExecutionException("Le paramètre username est obligatoire");
        }
        if (isBlank(password)) {
            throw new MojoExecutionException("Le paramètre password est obligatoire");
        }
    }

    private double resolveThreshold(XrayClient client)
            throws IOException, XrayClient.AuthenticationException, XrayClient.WatchNotFoundException {
        if ("default".equalsIgnoreCase(watch)) {
            return DEFAULT_THRESHOLD;
        }
        OptionalDouble threshold = client.fetchThresholdForWatch(watch);
        if (threshold.isPresent()) {
            return threshold.getAsDouble();
        }
        getLog().warn(String.format(Locale.ROOT,
                "Impossible de déterminer le seuil du watch '%s'. Utilisation du seuil par défaut %.1f.",
                watch, DEFAULT_THRESHOLD));
        return DEFAULT_THRESHOLD;
    }

    private Path getReportPath() {
        String buildDirectory = project != null && project.getBuild() != null
                ? project.getBuild().getDirectory()
                : "target";
        return Path.of(buildDirectory, "xray-scan-report.json");
    }

    private List<CveResult> filterViolationsByCompileScope(List<CveResult> violations) {
        if (violations == null || violations.isEmpty()) {
            return List.of();
        }
        Set<String> allowedNames = resolveCompileScopeDependencyNames();
        if (allowedNames.isEmpty()) {
            return List.of();
        }
        return violations.stream()
                .filter(violation -> matchesDependency(allowedNames, violation))
                .collect(Collectors.toList());
    }

    private Set<String> resolveCompileScopeDependencyNames() {
        if (project == null) {
            return Set.of();
        }
        Collection<Artifact> artifacts = project.getArtifacts();
        if (artifacts == null || artifacts.isEmpty()) {
            return Set.of();
        }
        Set<String> names = new HashSet<>();
        for (Artifact artifact : artifacts) {
            if (!isCompileScope(artifact)) {
                continue;
            }
            addArtifactNames(names, artifact);
        }
        return names;
    }

    private void addArtifactNames(Set<String> names, Artifact artifact) {
        if (artifact == null) {
            return;
        }
        String groupId = lowerCaseOrNull(artifact.getGroupId());
        String artifactId = lowerCaseOrNull(artifact.getArtifactId());
        String version = lowerCaseOrNull(artifact.getVersion());
        String classifier = lowerCaseOrNull(artifact.getClassifier());

        if (artifactId != null) {
            names.add(artifactId);
        }
        if (groupId != null && artifactId != null) {
            names.add(groupId + ":" + artifactId);
            names.add(groupId + "/" + artifactId);
            names.add("gav://" + groupId + ":" + artifactId);
        }
        if (groupId != null && artifactId != null && version != null) {
            names.add(groupId + ":" + artifactId + ":" + version);
            names.add(groupId + ":" + artifactId + ":" + version + (classifier != null ? ":" + classifier : ""));
            names.add(groupId + "/" + artifactId + "/" + version);
            names.add("gav://" + groupId + ":" + artifactId + ":" + version);
        }
        String id = lowerCaseOrNull(artifact.getId());
        if (id != null) {
            names.add(id);
        }
        String dependencyConflictId = lowerCaseOrNull(artifact.getDependencyConflictId());
        if (dependencyConflictId != null) {
            names.add(dependencyConflictId);
        }
    }

    private boolean matchesDependency(Set<String> allowedNames, CveResult violation) {
        if (violation == null) {
            return false;
        }
        String packageName = lowerCaseOrNull(violation.getPackageName());
        if (packageName == null) {
            return false;
        }
        if (allowedNames.contains(packageName)) {
            return true;
        }
        int lastColon = packageName.lastIndexOf(':');
        if (lastColon >= 0) {
            String candidate = packageName.substring(lastColon + 1);
            if (allowedNames.contains(candidate)) {
                return true;
            }
        }
        int lastSlash = packageName.lastIndexOf('/');
        if (lastSlash >= 0) {
            String candidate = packageName.substring(lastSlash + 1);
            if (allowedNames.contains(candidate)) {
                return true;
            }
        }
        return false;
    }

    private boolean isCompileScope(Artifact artifact) {
        String scope = artifact != null ? artifact.getScope() : null;
        if (scope == null || scope.isBlank()) {
            return true;
        }
        return Artifact.SCOPE_COMPILE.equals(scope);
    }

    private String lowerCaseOrNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        return trimmed.toLowerCase(Locale.ROOT);
    }

    private void logViolations(List<CveResult> violations) {
        if (violations.isEmpty()) {
            return;
        }
        getLog().info("Liste des vulnérabilités :");
        getLog().info("Colonnes : CVE | package | version | fixed-version | CVSS | sévérité");
        for (CveResult violation : violations) {
            String fixedVersion = violation.getFixedVersion();
            String fixedVersionColumn = (fixedVersion == null || fixedVersion.isBlank()) ? "-" : fixedVersion;
            getLog().info(String.format(Locale.ROOT,
                    "%s | %s | %s | %s | CVSS=%.1f | %s",
                    violation.getCveId(),
                    violation.getPackageName(),
                    violation.getVersion(),
                    fixedVersionColumn,
                    violation.getCvssScore(),
                    violation.getSeverity()));
        }
    }

    private boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }
}
