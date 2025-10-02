package com.mycompany.xrayscan;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
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

        XrayScanMojo mojo = newMojo("default", true);

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

        XrayScanMojo mojo = newMojo("critical-watch", true);

        assertThatThrownBy(mojo::execute)
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("vulnérabilité(s) critique(s)");
    }

    @Test
    void shouldRaiseFailureWhenAuthenticationFails() throws Exception {
        stubFor(get(urlPathEqualTo("/api/v2/violations"))
                .withQueryParam("watch", equalTo("default"))
                .willReturn(aResponse().withStatus(401)));

        XrayScanMojo mojo = newMojo("default", true);

        assertThatThrownBy(mojo::execute)
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("Authentification Xray");
    }

    private XrayScanMojo newMojo(String watch, boolean failOnThreshold) throws Exception {
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
        setField(mojo, "project", project);
        return mojo;
    }

    private void setField(Object target, String fieldName, Object value) throws Exception {
        var field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }
}
