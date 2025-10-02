package com.mycompany.xrayscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.util.List;
import java.util.Locale;
import java.util.OptionalDouble;

/**
 * Client HTTP léger pour consommer l'API JFrog Xray.
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

    public List<CveResult> fetchViolations(String watch) throws IOException, AuthenticationException, WatchNotFoundException {
        String encodedWatch = URLEncoder.encode(watch, StandardCharsets.UTF_8);
        URI uri = baseUri.resolve("violations?watch=" + encodedWatch);
        HttpRequest request = HttpRequest.newBuilder(uri)
                .header("Accept", "application/json")
                .header("Authorization", authorizationHeader)
                .GET()
                .build();

        HttpResponse<String> response = send(request);
        JsonNode root = parseJson(response);
        return extractViolations(root);
    }

    public OptionalDouble fetchThresholdForWatch(String watch) throws IOException, AuthenticationException, WatchNotFoundException {
        String encodedWatch = URLEncoder.encode(watch, StandardCharsets.UTF_8);
        URI uri = baseUri.resolve("watches/" + encodedWatch);
        HttpRequest request = HttpRequest.newBuilder(uri)
                .header("Accept", "application/json")
                .header("Authorization", authorizationHeader)
                .GET()
                .build();

        HttpResponse<String> response = send(request);
        JsonNode root = parseJson(response);
        OptionalDouble numericThreshold = findNumericThreshold(root);
        if (numericThreshold.isPresent()) {
            return numericThreshold;
        }
        String severity = findSeverityThreshold(root);
        if (severity != null) {
            return OptionalDouble.of(mapSeverityToScore(severity));
        }
        return OptionalDouble.empty();
    }

    private HttpResponse<String> send(HttpRequest request) throws IOException, AuthenticationException, WatchNotFoundException {
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();
            if (log != null && log.isDebugEnabled()) {
                log.debug("Appel Xray " + request.uri() + " -> HTTP " + status);
            }
            if (status == 401 || status == 403) {
                throw new AuthenticationException("HTTP " + status);
            }
            if (status == 404) {
                throw new WatchNotFoundException("HTTP 404");
            }
            if (status >= 400) {
                throw new IOException("Réponse HTTP " + status + " : " + response.body());
            }
            return response;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Requête interrompue", e);
        }
    }

    private JsonNode parseJson(HttpResponse<String> response) throws IOException {
        String body = response.body();
        if (body == null || body.isBlank()) {
            return mapper.createObjectNode();
        }
        return mapper.readTree(body);
    }

    private List<CveResult> extractViolations(JsonNode root) {
        List<CveResult> results = new ArrayList<>();
        JsonNode violationsNode = root.path("violations");
        if (!violationsNode.isArray()) {
            return results;
        }
        for (JsonNode violationNode : violationsNode) {
            String cveId = firstNonBlank(
                    violationNode.path("cve").asText(null),
                    violationNode.path("cve_id").asText(null),
                    violationNode.path("issue_id").asText(null));
            if (cveId == null && violationNode.has("cves") && violationNode.path("cves").isArray()) {
                JsonNode firstCve = violationNode.path("cves").get(0);
                if (firstCve != null) {
                    cveId = firstNonBlank(firstCve.path("cve").asText(null), firstCve.path("id").asText(null));
                }
            }
            String packageName = findPackageName(violationNode);
            String version = findPackageVersion(violationNode);
            double cvssScore = findCvssScore(violationNode);
            String severity = firstNonBlank(
                    violationNode.path("severity").asText(null),
                    violationNode.path("issue_severity").asText(null));
            String summary = firstNonBlank(
                    violationNode.path("summary").asText(null),
                    violationNode.path("description").asText(null));

            CveResult result = new CveResult(cveId, packageName, version, cvssScore, severity, summary);
            results.add(result);
        }
        return results;
    }

    private String findPackageName(JsonNode violationNode) {
        if (violationNode.has("components") && violationNode.path("components").isArray()) {
            JsonNode component = violationNode.path("components").get(0);
            if (component != null) {
                String compName = firstNonBlank(component.path("name").asText(null), component.path("component_name").asText(null));
                if (compName != null) {
                    return compName;
                }
            }
        }
        return firstNonBlank(
                violationNode.path("component").asText(null),
                violationNode.path("component_name").asText(null));
    }

    private String findPackageVersion(JsonNode violationNode) {
        if (violationNode.has("components") && violationNode.path("components").isArray()) {
            JsonNode component = violationNode.path("components").get(0);
            if (component != null) {
                String version = firstNonBlank(component.path("version").asText(null), component.path("component_version").asText(null));
                if (version != null) {
                    return version;
                }
            }
        }
        return firstNonBlank(
                violationNode.path("version").asText(null),
                violationNode.path("component_version").asText(null));
    }

    private double findCvssScore(JsonNode violationNode) {
        if (violationNode.has("cvss_score") && violationNode.path("cvss_score").isNumber()) {
            return violationNode.path("cvss_score").asDouble();
        }
        if (violationNode.has("cvss") && violationNode.path("cvss").has("score")) {
            return violationNode.path("cvss").path("score").asDouble(0.0);
        }
        if (violationNode.has("cves") && violationNode.path("cves").isArray()) {
            JsonNode firstCve = violationNode.path("cves").get(0);
            if (firstCve != null) {
                if (firstCve.has("cvss_v3_score")) {
                    return firstCve.path("cvss_v3_score").asDouble(0.0);
                }
                if (firstCve.has("cvss_v2_score")) {
                    return firstCve.path("cvss_v2_score").asDouble(0.0);
                }
            }
        }
        return 0.0;
    }

    private OptionalDouble findNumericThreshold(JsonNode root) {
        if (root.has("threshold") && root.path("threshold").isNumber()) {
            return OptionalDouble.of(root.path("threshold").asDouble());
        }
        if (root.has("cvss_min_score") && root.path("cvss_min_score").isNumber()) {
            return OptionalDouble.of(root.path("cvss_min_score").asDouble());
        }
        JsonNode policies = root.path("policies");
        if (policies.isArray()) {
            for (JsonNode policy : policies) {
                OptionalDouble threshold = findNumericThreshold(policy);
                if (threshold.isPresent()) {
                    return threshold;
                }
                JsonNode rules = policy.path("rules");
                if (rules.isArray()) {
                    for (JsonNode rule : rules) {
                        OptionalDouble ruleThreshold = findNumericThreshold(rule);
                        if (ruleThreshold.isPresent()) {
                            return ruleThreshold;
                        }
                    }
                }
            }
        }
        JsonNode rules = root.path("rules");
        if (rules.isArray()) {
            for (JsonNode rule : rules) {
                OptionalDouble ruleThreshold = findNumericThreshold(rule);
                if (ruleThreshold.isPresent()) {
                    return ruleThreshold;
                }
            }
        }
        JsonNode criteria = root.path("criteria");
        if (criteria.isObject()) {
            OptionalDouble criteriaThreshold = findNumericThreshold(criteria);
            if (criteriaThreshold.isPresent()) {
                return criteriaThreshold;
            }
        }
        return OptionalDouble.empty();
    }

    private String findSeverityThreshold(JsonNode root) {
        JsonNode severityNode = root.path("min_severity");
        if (severityNode.isTextual()) {
            return severityNode.asText();
        }
        JsonNode policies = root.path("policies");
        if (policies.isArray()) {
            for (JsonNode policy : policies) {
                String severity = findSeverityThreshold(policy);
                if (severity != null) {
                    return severity;
                }
            }
        }
        JsonNode rules = root.path("rules");
        if (rules.isArray()) {
            for (JsonNode rule : rules) {
                String severity = findSeverityThreshold(rule);
                if (severity != null) {
                    return severity;
                }
            }
        }
        JsonNode criteria = root.path("criteria");
        if (criteria.isObject()) {
            return findSeverityThreshold(criteria);
        }
        return null;
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

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private JsonNode parseJson(String body) throws IOException {
        if (body == null || body.isBlank()) {
            return mapper.createObjectNode();
        }
        return mapper.readTree(body);
    }

    private URI normalizeBaseUri(String baseUrl) {
        String normalized = baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";
        return URI.create(normalized);
    }

    private String buildAuthorizationHeader(String username, String password) {
        String credentials = username + ":" + password;
        String encoded = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        return "Basic " + encoded;
    }

    public static class AuthenticationException extends Exception {
        public AuthenticationException(String message) {
            super(message);
        }
    }

    public static class WatchNotFoundException extends Exception {
        public WatchNotFoundException(String message) {
            super(message);
        }
    }
}
