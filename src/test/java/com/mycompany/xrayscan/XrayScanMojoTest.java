package com.mycompany.xrayscan;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.artifact.versioning.VersionRange;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class XrayScanMojoTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @RegisterExtension
    static WireMockExtension wireMock = WireMockExtension.newInstance()
            .configureStaticDsl(true)
            .options(wireMockConfig().dynamicPort())
            .build();

    private Path buildDirectory;

    @BeforeEach
    void setUp() throws IOException {
        buildDirectory = Files.createTempDirectory("xray-scan-test");
    }

    @Test
    void shouldGenerateReportWithoutFailureWhenNoCveAboveThreshold() throws Exception {
        stubFor(get(urlPathEqualTo("/api/v2/violations"))
                .withQueryParam("watch", equalTo("default"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"violations\":[{" +
                                "\"cve\":\"CVE-2024-0001\"," +
                                "\"components\":[{\"name\":\"log4j-core\",\"version\":\"2.19.0\",\"fixed_versions\":[\"2.19.1\"]}]," +
                                "\"cvss_score\":6.5," +
                                "\"severity\":\"Medium\"," +
                                "\"summary\":\"Test vulnerability\"}]}")));

        XrayScanMojo mojo = newMojo("default", true,
                artifact("org.apache.logging.log4j", "log4j-core", "2.19.0", Artifact.SCOPE_COMPILE));

        mojo.execute();

        Path report = buildDirectory.resolve("xray-scan-report.json");
        assertThat(Files.exists(report)).isTrue();
        JsonNode results = MAPPER.readTree(report.toFile());
        assertThat(results.isArray()).isTrue();
        assertThat(results.size()).isEqualTo(1);
        assertThat(results.get(0).path("cvssScore").asDouble()).isEqualTo(6.5);
        assertThat(results.get(0).path("fixedVersion").asText()).isEqualTo("2.19.1");
    }

    @Test
    void shouldFailBuildWhenVulnerabilityAboveThreshold() throws Exception {
        stubFor(get(urlPathEqualTo("/api/v2/violations"))
                .withQueryParam("watch", equalTo("critical-watch"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"violations\":[{" +
                                "\"cve\":\"CVE-2024-9999\"," +
                                "\"components\":[{\"name\":\"commons-io\",\"version\":\"2.6\",\"fixed_versions\":[\"2.7\"]}]," +
                                "\"cvss_score\":9.1," +
                                "\"severity\":\"Critical\"," +
                                "\"summary\":\"Critical vulnerability\"}]}")));
        stubFor(get(urlPathEqualTo("/api/v2/watches/critical-watch"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"threshold\":8.5}")));

        XrayScanMojo mojo = newMojo("critical-watch", true,
                artifact("commons-io", "commons-io", "2.6", Artifact.SCOPE_COMPILE));

        assertThatThrownBy(mojo::execute)
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("vulnérabilité(s) critique(s)");
    }

    @Test
    void shouldIncludeAllViolationsInGeneratedReport() throws Exception {
        stubFor(get(urlPathEqualTo("/api/v2/violations"))
                .withQueryParam("watch", equalTo("custom-watch"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"violations\":[{" +
                                "\"cve\":\"CVE-2024-1234\"," +
                                "\"components\":[{\"name\":\"commons-io\",\"version\":\"2.6\",\"fixed_versions\":[\"2.7\"]}]," +
                                "\"cvss_score\":9.1," +
                                "\"severity\":\"Critical\"," +
                                "\"summary\":\"Critical vulnerability\"},{" +
                                "\"cve\":\"CVE-2024-5678\"," +
                                "\"components\":[{\"name\":\"guava\",\"version\":\"32.0\",\"fixed_versions\":[\"32.1\"]}]," +
                                "\"cvss_score\":4.3," +
                                "\"severity\":\"Medium\"," +
                                "\"summary\":\"Moderate vulnerability\"}]}")));
        stubFor(get(urlPathEqualTo("/api/v2/watches/custom-watch"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"threshold\":8.5}")));

        XrayScanMojo mojo = newMojo("custom-watch", true,
                artifact("commons-io", "commons-io", "2.6", Artifact.SCOPE_COMPILE),
                artifact("com.google.guava", "guava", "32.0", Artifact.SCOPE_COMPILE));

        assertThatThrownBy(mojo::execute)
                .isInstanceOf(MojoFailureException.class);

        Path report = buildDirectory.resolve("xray-scan-report.json");
        assertThat(Files.exists(report)).isTrue();
        JsonNode results = MAPPER.readTree(report.toFile());
        assertThat(results.isArray()).isTrue();
        assertThat(results.size()).isEqualTo(2);

        JsonNode first = results.get(0);
        JsonNode second = results.get(1);

        assertThat(first.path("cveId").asText()).isEqualTo("CVE-2024-1234");
        assertThat(first.path("fixedVersion").asText()).isEqualTo("2.7");

        assertThat(second.path("cveId").asText()).isEqualTo("CVE-2024-5678");
        assertThat(second.path("fixedVersion").asText()).isEqualTo("32.1");
    }

    @Test
    void shouldRaiseFailureWhenAuthenticationFails() throws Exception {
        stubFor(get(urlPathEqualTo("/api/v2/violations"))
                .withQueryParam("watch", equalTo("default"))
                .willReturn(aResponse().withStatus(401)));

        XrayScanMojo mojo = newMojo("default", true,
                artifact("org.apache.logging.log4j", "log4j-core", "2.19.0", Artifact.SCOPE_COMPILE));

        assertThatThrownBy(mojo::execute)
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("Authentification Xray");
    }

    @Test
    void shouldIgnoreViolationsOutsideCompileScope() throws Exception {
        stubFor(get(urlPathEqualTo("/api/v2/violations"))
                .withQueryParam("watch", equalTo("default"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"violations\":[{" +
                                "\"cve\":\"CVE-2024-7777\"," +
                                "\"components\":[{\"name\":\"junit-jupiter\",\"version\":\"5.10.2\"}]," +
                                "\"cvss_score\":9.3," +
                                "\"severity\":\"Critical\"," +
                                "\"summary\":\"Test scope vulnerability\"}]}")));

        XrayScanMojo mojo = newMojo("default", true,
                artifact("org.junit.jupiter", "junit-jupiter", "5.10.2", Artifact.SCOPE_TEST));

        mojo.execute();

        Path report = buildDirectory.resolve("xray-scan-report.json");
        assertThat(Files.exists(report)).isTrue();
        JsonNode results = MAPPER.readTree(report.toFile());
        assertThat(results.isArray()).isTrue();
        assertThat(results).isEmpty();
    }

    @Test
    void shouldConsiderDependenciesWithoutExplicitScope() throws Exception {
        stubFor(get(urlPathEqualTo("/api/v2/violations"))
                .withQueryParam("watch", equalTo("default"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"violations\":[{" +
                                "\"cve\":\"CVE-2024-8888\"," +
                                "\"components\":[{\"name\":\"custom-lib\",\"version\":\"1.0.0\"}]," +
                                "\"cvss_score\":9.0," +
                                "\"severity\":\"Critical\"," +
                                "\"summary\":\"Default scope vulnerability\"}]}")));

        XrayScanMojo mojo = newMojo("default", true,
                artifact("com.mycompany", "custom-lib", "1.0.0", null));

        assertThatThrownBy(mojo::execute)
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("vulnérabilité(s) critique(s)");
    }

    @Test
    void shouldEncodeCustomWatchNamesForThresholdLookup() throws Exception {
        stubFor(get(urlPathEqualTo("/api/v2/violations"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"violations\":[]}")));
        stubFor(get(urlPathEqualTo("/api/v2/watches/custom%20watch"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"threshold\":7.0}")));

        XrayScanMojo mojo = newMojo("custom watch", true,
                artifact("org.apache.logging.log4j", "log4j-core", "2.19.0", Artifact.SCOPE_COMPILE));

        mojo.execute();

        Path report = buildDirectory.resolve("xray-scan-report.json");
        assertThat(Files.exists(report)).isTrue();
        JsonNode results = MAPPER.readTree(report.toFile());
        assertThat(results.isArray()).isTrue();
        assertThat(results).isEmpty();

        verify(getRequestedFor(urlPathEqualTo("/api/v2/violations"))
                .withQueryParam("watch", equalTo("custom watch")));
        verify(getRequestedFor(urlPathEqualTo("/api/v2/watches/custom%20watch")));
    }

    private XrayScanMojo newMojo(String watch, boolean failOnThreshold, Artifact... artifacts) throws Exception {
        XrayScanMojo mojo = new XrayScanMojo();
        setField(mojo, "xrayUrl", wireMock.baseUrl() + "/api/v2");
        setField(mojo, "username", "user");
        setField(mojo, "password", "pass");
        setField(mojo, "watch", watch);
        setField(mojo, "failOnThreshold", failOnThreshold);
        setField(mojo, "timeoutSeconds", 30);
        setField(mojo, "skip", false);

        MavenProject project = new MavenProject();
        Build build = new Build();
        build.setDirectory(buildDirectory.toString());
        project.setBuild(build);
        Set<Artifact> artifactSet = new LinkedHashSet<>(Arrays.asList(artifacts));
        project.setArtifacts(artifactSet);
        project.setDependencyArtifacts(artifactSet);
        setField(mojo, "project", project);
        return mojo;
    }

    private Artifact artifact(String groupId, String artifactId, String version, String scope) {
        DefaultArtifactHandler handler = new DefaultArtifactHandler("jar");
        DefaultArtifact artifact = new DefaultArtifact(groupId, artifactId,
                VersionRange.createFromVersion(version), scope, "jar", null, handler);
        artifact.setFile(null);
        return artifact;
    }

    private void setField(Object target, String fieldName, Object value) throws Exception {
        var field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }
}
