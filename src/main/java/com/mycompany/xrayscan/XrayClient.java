package com.mycompany.xrayscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.mycompany.xrayscan.model.CveResult;
import org.apache.maven.plugin.logging.Log;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Client HTTP dédié à la consommation de l'API JFrog Xray (REST v2).
 */
public class XrayClient {

    private static final double DEFAULT_CRITICAL_THRESHOLD = 9.0;
    private static final double DEFAULT_HIGH_THRESHOLD = 7.0;
    private static final double DEFAULT_MEDIUM_THRESHOLD = 4.0;
    private static final double DEFAULT_LOW_THRESHOLD = 0.0;

    private final URI baseUri;
    private final HttpClient httpClient;
    private final ObjectMapper mapper;
    private final String authorizationHeader;
    private final Log log;

    public XrayClient(String baseUrl, String username, String password, Duration timeout, Log log) {
        this.baseUri = normalizeBaseUri(baseUrl);
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .build();
        this.mapper = new ObjectMapper();
        this.authorizationHeader = buildAuthorizationHeader(username, password);
        this.log = log;
    }

    public List<CveResult> fetchViolations(String watch) throws IOException, AuthenticationException {
        StringBuilder path = new StringBuilder("violations");
        if (watch != null && !watch.isBlank()) {
            path.append("?watch=").append(encodeQueryParam(watch));
        }
        URI uri = buildUri(path.toString());
        HttpRequest request = HttpRequest.newBuilder(uri)
                .header("Accept", "application/json")
                .header("Authorization", authorizationHeader)
                .GET()
                .build();

        HttpResponse<String> response = send(request, Set.of(200));
        JsonNode body = parseJson(response.body());
        return parseViolations(body);
    }

    public Double fetchWatchThreshold(String watch) throws IOException, AuthenticationException {
        if (watch == null || watch.isBlank()) {
            return null;
        }
        URI uri = buildUri("watches/" + encodePathSegment(watch));
        HttpRequest request = HttpRequest.newBuilder(uri)
                .header("Accept", "application/json")
                .header("Authorization", authorizationHeader)
                .GET()
                .build();

        HttpResponse<String> response = send(request, Set.of(200));
        JsonNode body = parseJson(response.body());
        double threshold = extractThresholdFromWatch(body);
        return threshold > 0 ? threshold : null;
    }

    private List<CveResult> parseViolations(JsonNode root) {
        if (root == null || root.isMissingNode()) {
            return List.of();
        }
        Set<CveResult> results = new LinkedHashSet<>();
        JsonNode violations = root.path("violations");
        if (violations.isArray()) {
            for (JsonNode violation : violations) {
                collectResultsFromViolation(violation, results);
            }
        }
        JsonNode vulnerabilities = root.path("vulnerabilities");
        if (vulnerabilities.isArray()) {
            for (JsonNode vulnerability : vulnerabilities) {
                collectResultsFromViolation(vulnerability, results);
            }
        }
        return new ArrayList<>(results);
    }

    private void collectResultsFromViolation(JsonNode violation, Set<CveResult> target) {
        if (violation == null || violation.isMissingNode()) {
            return;
        }
        String severity = violation.path("severity").asText("");
        String summary = violation.path("summary").asText("");
        String cveId = resolveCveId(violation);
        double cvssScore = resolveCvssScore(violation, severity);

        JsonNode components = violation.path("components");
        if (components.isArray() && components.size() > 0) {
            for (JsonNode component : components) {
                String name = component.path("name").asText("");
                String version = component.path("version").asText("");
                String fixedVersion = firstTextFromArray(component.path("fixed_versions"));
                if (fixedVersion.isBlank()) {
                    fixedVersion = firstTextFromArray(component.path("fixedVersions"));
                }
                target.add(new CveResult(cveId, name, version, cvssScore, severity, summary, fixedVersion));
            }
            return;
        }

        JsonNode impacted = violation.path("impacted_artifacts");
        if (impacted.isArray() && impacted.size() > 0) {
            for (JsonNode component : impacted) {
                String name = component.path("name").asText("");
                String version = component.path("version").asText("");
                String fixedVersion = firstTextFromArray(component.path("fixed_versions"));
                target.add(new CveResult(cveId, name, version, cvssScore, severity, summary, fixedVersion));
            }
            return;
        }

        target.add(new CveResult(cveId, "", "", cvssScore, severity, summary, ""));
    }

    private String resolveCveId(JsonNode violation) {
        if (violation == null) {
            return "";
        }
        String direct = violation.path("cve").asText(null);
        if (direct != null && !direct.isBlank()) {
            return direct;
        }
        ArrayNode cves = violation.path("cves").isArray() ? (ArrayNode) violation.path("cves") : null;
        if (cves != null && cves.size() > 0) {
            for (JsonNode cveNode : cves) {
                String candidate = cveNode.path("cve").asText(null);
                if (candidate == null || candidate.isBlank()) {
                    candidate = cveNode.path("id").asText(null);
                }
                if (candidate != null && !candidate.isBlank()) {
                    return candidate;
                }
            }
        }
        String issueId = violation.path("issue_id").asText(null);
        if (issueId != null && !issueId.isBlank()) {
            return issueId;
        }
        return "";
    }

    private double resolveCvssScore(JsonNode violation, String severity) {
        double direct = parseScore(violation.path("cvssScore"));
        if (direct <= 0) {
            direct = parseScore(violation.path("cvss_score"));
        }
        if (direct <= 0) {
            direct = parseScore(violation.path("cvss_v3_score"));
        }
        if (direct <= 0) {
            direct = parseScore(violation.path("cvss_v2_score"));
        }
        if (direct > 0) {
            return direct;
        }
        ArrayNode cves = violation.path("cves").isArray() ? (ArrayNode) violation.path("cves") : null;
        if (cves != null) {
            for (JsonNode cveNode : cves) {
                double score = parseScore(cveNode.path("cvss_v3_score"));
                if (score <= 0) {
                    score = parseScore(cveNode.path("cvss_v2_score"));
                }
                if (score > 0) {
                    return score;
                }
            }
        }
        return mapSeverityToScore(severity);
    }

    private double extractThresholdFromWatch(JsonNode watchNode) {
        if (watchNode == null || watchNode.isMissingNode()) {
            return 0.0;
        }
        double threshold = parseScore(watchNode.path("threshold"));
        if (threshold > 0) {
            return threshold;
        }
        String severity = watchNode.path("severity").asText(null);
        if (severity != null && !severity.isBlank()) {
            return mapSeverityToScore(severity);
        }
        double fromRules = extractThresholdFromPolicyRules(watchNode.path("policy_rules"));
        if (fromRules > 0) {
            return fromRules;
        }
        JsonNode policies = watchNode.path("policies");
        if (policies.isArray()) {
            for (JsonNode policy : policies) {
                double candidate = extractThresholdFromPolicyRules(policy.path("policy_rules"));
                if (candidate > 0) {
                    return candidate;
                }
                candidate = extractThresholdFromPolicyRules(policy.path("rules"));
                if (candidate > 0) {
                    return candidate;
                }
            }
        }
        return 0.0;
    }

    private double extractThresholdFromPolicyRules(JsonNode rulesNode) {
        if (!rulesNode.isArray()) {
            return 0.0;
        }
        double minThreshold = Double.POSITIVE_INFINITY;
        for (JsonNode rule : rulesNode) {
            double candidate = parseScore(rule.path("threshold"));
            if (candidate > 0) {
                minThreshold = Math.min(minThreshold, candidate);
            }
            JsonNode criteria = rule.path("criteria");
            if (criteria.isMissingNode()) {
                criteria = rule;
            }
            double cvss = parseScore(criteria.path("cvss_threshold"));
            if (cvss > 0) {
                minThreshold = Math.min(minThreshold, cvss);
            }
            String minSeverity = criteria.path("min_severity").asText(null);
            if (minSeverity != null && !minSeverity.isBlank()) {
                minThreshold = Math.min(minThreshold, mapSeverityToScore(minSeverity));
            }
        }
        return minThreshold == Double.POSITIVE_INFINITY ? 0.0 : minThreshold;
    }

    private HttpResponse<String> send(HttpRequest request, Set<Integer> allowedStatuses)
            throws IOException, AuthenticationException {
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();
            if (log != null && log.isDebugEnabled()) {
                log.debug("Appel Xray " + request.uri() + " -> HTTP " + status);
            }
            if (status == 401 || status == 403) {
                throw new AuthenticationException("HTTP " + status);
            }
            if (allowedStatuses.contains(status)) {
                return response;
            }
            if (status >= 400) {
                throw new IOException("Réponse HTTP " + status + " : " + response.body());
            }
            if (!allowedStatuses.isEmpty()) {
                throw new IOException("Réponse HTTP inattendue : " + status);
            }
            return response;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Requête interrompue", e);
        }
    }

    private JsonNode parseJson(String body) throws IOException {
        if (body == null || body.isBlank()) {
            return mapper.createObjectNode();
        }
        return mapper.readTree(body);
    }

    private URI buildUri(String suffix) {
        if (suffix == null || suffix.isBlank()) {
            return baseUri;
        }
        if (suffix.startsWith("/")) {
            return baseUri.resolve(suffix.substring(1));
        }
        return baseUri.resolve(suffix);
    }

    private URI normalizeBaseUri(String baseUrl) {
        Objects.requireNonNull(baseUrl, "baseUrl");
        String normalized = baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";
        return URI.create(normalized);
    }

    private String buildAuthorizationHeader(String username, String password) {
        String credentials = (username != null ? username : "") + ":" + (password != null ? password : "");
        String encoded = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        return "Basic " + encoded;
    }

    private String encodeQueryParam(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private String encodePathSegment(String value) {
        return encodeQueryParam(value).replace("%2F", "/");
    }

    private String firstTextFromArray(JsonNode node) {
        if (node == null || !node.isArray()) {
            return "";
        }
        for (JsonNode element : node) {
            if (element != null) {
                String text = element.asText(null);
                if (text != null && !text.isBlank()) {
                    return text;
                }
            }
        }
        return "";
    }

    private double parseScore(JsonNode node) {
        if (node == null || node.isMissingNode()) {
            return 0.0;
        }
        if (node.isNumber()) {
            return node.asDouble();
        }
        if (node.isTextual()) {
            try {
                return Double.parseDouble(node.asText());
            } catch (NumberFormatException ignored) {
                return 0.0;
            }
        }
        return 0.0;
    }

    private double mapSeverityToScore(String severity) {
        if (severity == null) {
            return DEFAULT_HIGH_THRESHOLD;
        }
        switch (severity.toLowerCase(Locale.ROOT)) {
            case "critical":
                return DEFAULT_CRITICAL_THRESHOLD;
            case "high":
                return DEFAULT_HIGH_THRESHOLD;
            case "medium":
            case "moderate":
                return DEFAULT_MEDIUM_THRESHOLD;
            case "low":
                return DEFAULT_LOW_THRESHOLD;
            default:
                return DEFAULT_HIGH_THRESHOLD;
        }
    }

    public static class AuthenticationException extends Exception {
        public AuthenticationException(String message) {
            super(message);
        }
    }
}
