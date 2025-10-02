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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.HexFormat;

/**
 * Client HTTP léger pour consommer l'API JFrog Xray.
 */
public class XrayClient {

    private static final String GRAPH_SCAN_PATH = "../v1/scan/graph";
    private static final String SCAN_BINARY_PATH = "scanBinary";
    private static final String SCAN_TYPE_DEPENDENCY = "dependency";
    private static final Duration DEFAULT_POLL_INTERVAL = Duration.ofSeconds(3);
    private static final Duration DEFAULT_POLL_TIMEOUT = Duration.ofMinutes(15);

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

    public List<CveResult> runDependencyScan(String rootComponentId, Set<String> dependencyComponentIds)
            throws IOException, AuthenticationException {
        if (rootComponentId == null || rootComponentId.isBlank()) {
            return List.of();
        }
        GraphNode root = new GraphNode(rootComponentId.trim());
        if (dependencyComponentIds != null) {
            dependencyComponentIds.stream()
                    .filter(Objects::nonNull)
                    .map(String::trim)
                    .filter(value -> !value.isEmpty())
                    .map(GraphNode::new)
                    .forEach(root::addNode);
        }
        return executeScan(root, SCAN_TYPE_DEPENDENCY);
    }

    public List<CveResult> scanArchive(Path archive, String watch)
            throws IOException, AuthenticationException {
        if (archive == null) {
            return List.of();
        }
        if (!Files.exists(archive) || !Files.isRegularFile(archive)) {
            throw new IOException("Archive à scanner introuvable : " + archive);
        }

        byte[] content = Files.readAllBytes(archive);
        if (content.length == 0 && log != null) {
            log.warn("Archive fournie à Xray vide : " + archive);
        }

        String encoded = Base64.getEncoder().encodeToString(content);
        String sha256 = computeSha256(content);
        long size = content.length;
        String filename = archive.getFileName() != null ? archive.getFileName().toString() : "archive";

        var body = mapper.createObjectNode();
        body.put("data", encoded);
        body.put("filename", filename);
        body.put("sha256", sha256);
        body.put("size", size);
        if (watch != null && !watch.isBlank()) {
            body.put("watch", watch);
        }

        URI scanUri = baseUri.resolve(SCAN_BINARY_PATH);
        HttpRequest request = HttpRequest.newBuilder(scanUri)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .header("Authorization", authorizationHeader)
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .build();

        HttpResponse<String> response = send(request, Set.of(200, 202));
        JsonNode root = parseJson(response.body());
        return extractScanResults(root);
    }

    private List<CveResult> executeScan(GraphNode graph, String scanType)
            throws IOException, AuthenticationException {
        if (graph == null) {
            return List.of();
        }
        String requestBody = mapper.writeValueAsString(graph);
        URI scanUri = buildGraphScanUri("?scan_type=" + scanType);
        HttpRequest request = HttpRequest.newBuilder(scanUri)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .header("Authorization", authorizationHeader)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> response = send(request, Set.of(200, 201));
        JsonNode root = parseJson(response.body());
        String scanId = root.path("scan_id").asText(null);
        if (scanId == null || scanId.isBlank()) {
            throw new IOException("Réponse Xray invalide : scan_id manquant");
        }
        return pollScanResults(scanId);
    }

    private List<CveResult> pollScanResults(String scanId)
            throws IOException, AuthenticationException {
        Duration timeout = DEFAULT_POLL_TIMEOUT;
        long deadline = System.nanoTime() + timeout.toNanos();
        URI resultsUri = buildGraphScanUri("/" + encodePathSegment(scanId) + "?include_vulnerabilities=true");

        while (true) {
            HttpRequest request = HttpRequest.newBuilder(resultsUri)
                    .header("Accept", "application/json")
                    .header("Authorization", authorizationHeader)
                    .GET()
                    .build();

            HttpResponse<String> response = send(request, Set.of(200, 202));
            if (response.statusCode() == 202) {
                if (System.nanoTime() > deadline) {
                    throw new IOException("Timeout lors de la récupération des résultats de scan Xray");
                }
                sleep(DEFAULT_POLL_INTERVAL);
                continue;
            }

            JsonNode root = parseJson(response.body());
            return extractScanResults(root);
        }
    }

    private List<CveResult> extractScanResults(JsonNode root) {
        Set<CveResult> uniqueResults = new LinkedHashSet<>();
        if (root == null || root.isMissingNode()) {
            return List.of();
        }
        JsonNode violations = root.path("violations");
        if (violations.isArray()) {
            for (JsonNode violation : violations) {
                collectResultsFromIssue(violation, uniqueResults);
            }
        }
        JsonNode vulnerabilities = root.path("vulnerabilities");
        if (vulnerabilities.isArray()) {
            for (JsonNode vulnerability : vulnerabilities) {
                collectResultsFromIssue(vulnerability, uniqueResults);
            }
        }
        return new ArrayList<>(uniqueResults);
    }

    private void collectResultsFromIssue(JsonNode issueNode, Set<CveResult> target) {
        if (issueNode == null || issueNode.isMissingNode()) {
            return;
        }
        String severity = issueNode.path("severity").asText(null);
        String summary = issueNode.path("summary").asText(null);
        String cveId = resolveCveId(issueNode);
        double cvssScore = resolveCvssScore(issueNode, severity);
        JsonNode componentsNode = issueNode.path("components");
        if (componentsNode != null && componentsNode.isObject() && componentsNode.size() > 0) {
            Iterator<Map.Entry<String, JsonNode>> fields = componentsNode.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String componentId = entry.getKey();
                PackageInfo info = parseComponentId(componentId);
                JsonNode componentDetails = entry.getValue();
                String fixedVersion = resolveFixedVersion(componentDetails);
                CveResult result = new CveResult(
                        cveId,
                        info.packageName,
                        info.version,
                        cvssScore,
                        severity != null ? severity : "",
                        summary,
                        fixedVersion);
                target.add(result);
            }
        } else if (componentsNode != null && componentsNode.isArray() && componentsNode.size() > 0) {
            for (JsonNode componentNode : componentsNode) {
                PackageInfo info = parseComponentNode(componentNode);
                String fixedVersion = resolveFixedVersion(componentNode);
                CveResult result = new CveResult(
                        cveId,
                        info.packageName,
                        info.version,
                        cvssScore,
                        severity != null ? severity : "",
                        summary,
                        fixedVersion);
                target.add(result);
            }
        } else {
            // Fallback without component mapping
            CveResult result = new CveResult(
                    cveId,
                    "",
                    "",
                    cvssScore,
                    severity != null ? severity : "",
                    summary,
                    "");
            target.add(result);
        }
    }

    private String resolveCveId(JsonNode issueNode) {
        if (issueNode == null) {
            return "";
        }
        ArrayNode cves = issueNode.path("cves").isArray() ? (ArrayNode) issueNode.path("cves") : null;
        if (cves != null && cves.size() > 0) {
            JsonNode first = cves.get(0);
            if (first != null) {
                String id = first.path("cve").asText(null);
                if (id == null || id.isBlank()) {
                    id = first.path("id").asText(null);
                }
                if (id != null && !id.isBlank()) {
                    return id;
                }
            }
        }
        String issueId = issueNode.path("issue_id").asText(null);
        if (issueId != null && !issueId.isBlank()) {
            return issueId;
        }
        return "";
    }

    private double resolveCvssScore(JsonNode issueNode, String severity) {
        if (issueNode == null) {
            return 0.0;
        }
        ArrayNode cves = issueNode.path("cves").isArray() ? (ArrayNode) issueNode.path("cves") : null;
        if (cves != null) {
            for (JsonNode cve : cves) {
                double score = parseScore(cve.path("cvss_v3_score"));
                if (score <= 0) {
                    score = parseScore(cve.path("cvss_v2_score"));
                }
                if (score <= 0) {
                    score = parseScore(cve.path("cvss_v3"));
                }
                if (score > 0) {
                    return score;
                }
            }
        }
        JsonNode cvssNode = issueNode.path("cvss");
        if (cvssNode != null && cvssNode.isObject()) {
            double v3Score = parseScore(cvssNode.path("v3").path("score"));
            if (v3Score > 0) {
                return v3Score;
            }
            double v2Score = parseScore(cvssNode.path("v2").path("score"));
            if (v2Score > 0) {
                return v2Score;
            }
        }
        double issueScore = parseScore(issueNode.path("cvss_v3_score"));
        if (issueScore <= 0) {
            issueScore = parseScore(issueNode.path("cvss_v2_score"));
        }
        if (issueScore > 0) {
            return issueScore;
        }
        return mapSeverityToScore(severity);
    }

    private String resolveFixedVersion(JsonNode componentDetails) {
        String fixedVersion = firstTextFromArray(componentDetails.path("fixed_versions"));
        if (fixedVersion == null || fixedVersion.isBlank()) {
            fixedVersion = firstTextFromArray(componentDetails.path("fixedVersions"));
        }
        return fixedVersion != null ? fixedVersion : "";
    }

    private PackageInfo parseComponentNode(JsonNode componentNode) {
        if (componentNode == null || componentNode.isMissingNode()) {
            return new PackageInfo("", "");
        }
        String componentId = componentNode.path("component_id").asText(null);
        if (componentId == null || componentId.isBlank()) {
            componentId = componentNode.path("componentId").asText(null);
        }
        if (componentId != null && !componentId.isBlank()) {
            return parseComponentId(componentId);
        }
        String packageName = componentNode.path("package_name").asText(null);
        if (packageName == null || packageName.isBlank()) {
            packageName = componentNode.path("name").asText(null);
        }
        String version = componentNode.path("version").asText(null);
        return new PackageInfo(packageName != null ? packageName : "", version != null ? version : "");
    }

    private String computeSha256(byte[] content) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content);
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("Algorithme SHA-256 indisponible", e);
        }
    }

    private double parseScore(JsonNode node) {
        if (node == null || node.isMissingNode()) {
            return 0.0;
        }
        if (node.isNumber()) {
            return node.asDouble();
        }
        if (node.isTextual()) {
            String text = node.asText();
            try {
                return Double.parseDouble(text);
            } catch (NumberFormatException ignored) {
                return 0.0;
            }
        }
        return 0.0;
    }

    private PackageInfo parseComponentId(String componentId) {
        if (componentId == null || componentId.isBlank()) {
            return new PackageInfo("", "");
        }
        String normalized = componentId.trim();
        int schemeIndex = normalized.indexOf("://");
        if (schemeIndex >= 0) {
            normalized = normalized.substring(schemeIndex + 3);
        }
        String[] parts = normalized.split(":");
        if (parts.length >= 3) {
            String name = parts[0] + ":" + parts[1];
            StringBuilder versionBuilder = new StringBuilder(parts[2]);
            for (int i = 3; i < parts.length; i++) {
                if (!parts[i].isBlank()) {
                    versionBuilder.append(":").append(parts[i]);
                }
            }
            return new PackageInfo(name, versionBuilder.toString());
        }
        if (parts.length == 2) {
            return new PackageInfo(parts[0], parts[1]);
        }
        return new PackageInfo(normalized, "");
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

    private void sleep(Duration duration) throws IOException {
        try {
            Thread.sleep(Math.max(duration.toMillis(), 50));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Attente interrompue", e);
        }
    }

    private JsonNode parseJson(String body) throws IOException {
        if (body == null || body.isBlank()) {
            return mapper.createObjectNode();
        }
        return mapper.readTree(body);
    }

    private URI buildGraphScanUri(String suffix) {
        URI graphBase = baseUri.resolve(GRAPH_SCAN_PATH);
        String base = graphBase.toString();
        if (suffix == null || suffix.isBlank()) {
            return graphBase;
        }
        if (suffix.startsWith("?")) {
            return URI.create(base + suffix);
        }
        if (suffix.startsWith("/")) {
            return URI.create(base + suffix);
        }
        return URI.create(base + "/" + suffix);
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

    private String encodePathSegment(String value) {
        if (value == null) {
            return "";
        }
        String encoded = URLEncoder.encode(value, StandardCharsets.UTF_8);
        return encoded.replace("+", "%20");
    }

    private String firstTextFromArray(JsonNode arrayNode) {
        if (arrayNode == null || !arrayNode.isArray()) {
            return "";
        }
        for (JsonNode element : arrayNode) {
            if (element != null) {
                String text = element.asText(null);
                if (text != null && !text.isBlank()) {
                    return text;
                }
            }
        }
        return "";
    }

    public static class AuthenticationException extends Exception {
        public AuthenticationException(String message) {
            super(message);
        }
    }

    private static class GraphNode {
        private final String component_id;
        private final List<GraphNode> nodes = new ArrayList<>();

        GraphNode(String componentId) {
            this.component_id = componentId;
        }

        void addNode(GraphNode child) {
            if (child != null) {
                nodes.add(child);
            }
        }

        public String getComponent_id() {
            return component_id;
        }

        public List<GraphNode> getNodes() {
            return nodes;
        }
    }

    private static class PackageInfo {
        private final String packageName;
        private final String version;

        PackageInfo(String packageName, String version) {
            this.packageName = packageName;
            this.version = version;
        }
    }
}
