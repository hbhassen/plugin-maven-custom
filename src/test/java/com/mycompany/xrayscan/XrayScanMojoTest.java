package com.mycompany.xrayscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
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
    void shouldUploadMainArtifactAndGenerateReport() throws Exception {
        byte[] jarContent = "fake-jar".getBytes(StandardCharsets.UTF_8);
        Path artifactFile = buildDirectory.resolve("demo-app-1.0.0.jar");
        Files.write(artifactFile, jarContent);

        stubFor(post(urlPathEqualTo("/api/v2/scanBinary"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"violations\":[{" +
                                "\"issue_id\":\"XRAY-0001\"," +
                                "\"summary\":\"Test vulnerability\"," +
                                "\"severity\":\"Medium\"," +
                                "\"cves\":[{\"cve\":\"CVE-2024-0001\",\"cvss_v3_score\":6.5}]," +
                                "\"components\":[{\"package_name\":\"log4j-core\",\"version\":\"2.19.0\",\"fixed_versions\":[\"2.19.1\"]}]}]}")));

        Artifact mainArtifact = artifact("com.example", "demo-app", "1.0.0", Artifact.SCOPE_COMPILE, artifactFile);
        Artifact dependency = artifact("org.apache.logging.log4j", "log4j-core", "2.19.0", Artifact.SCOPE_COMPILE, null);
        XrayScanMojo mojo = newMojo(mainArtifact, "default-watch", true, dependency);

        mojo.execute();

        Path report = buildDirectory.resolve("xray-scan-report.json");
        assertThat(Files.exists(report)).isTrue();
        JsonNode results = MAPPER.readTree(report.toFile());
        assertThat(results.isArray()).isTrue();
        assertThat(results).hasSize(1);
        assertThat(results.get(0).path("cvssScore").asDouble()).isEqualTo(6.5);

        String expectedBase64 = Base64.getEncoder().encodeToString(jarContent);
        verify(postRequestedFor(urlPathEqualTo("/api/v2/scanBinary"))
                .withRequestBody(matchingJsonPath("$.watch", equalTo("default-watch")))
                .withRequestBody(matchingJsonPath("$.filename", equalTo("demo-app-1.0.0.jar")))
                .withRequestBody(matchingJsonPath("$.data", equalTo(expectedBase64))));
    }

    @Test
    void shouldFailBuildWhenViolationAboveThreshold() throws Exception {
        byte[] jarContent = "artifact".getBytes(StandardCharsets.UTF_8);
        Path artifactFile = buildDirectory.resolve("commons-io-2.6.jar");
        Files.write(artifactFile, jarContent);

        stubFor(post(urlPathEqualTo("/api/v2/scanBinary"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"violations\":[{" +
                                "\"issue_id\":\"XRAY-9999\"," +
                                "\"summary\":\"Critical vulnerability\"," +
                                "\"severity\":\"Critical\"," +
                                "\"cves\":[{\"cve\":\"CVE-2024-9999\",\"cvss_v3_score\":9.1}]," +
                                "\"components\":[{\"package_name\":\"commons-io\",\"version\":\"2.6\",\"fixed_versions\":[\"2.7\"]}]}]}")));

        Artifact mainArtifact = artifact("commons-io", "commons-io", "2.6", Artifact.SCOPE_COMPILE, artifactFile);
        Artifact dependency = artifact("commons-io", "commons-io", "2.6", Artifact.SCOPE_COMPILE, null);
        XrayScanMojo mojo = newMojo(mainArtifact, "critical-watch", true, dependency);

        assertThatThrownBy(mojo::execute)
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("vulnérabilité(s) critique(s)");

        verify(postRequestedFor(urlPathEqualTo("/api/v2/scanBinary"))
                .withRequestBody(matchingJsonPath("$.watch", equalTo("critical-watch"))));
    }

    @Test
    void shouldZipTargetDirectoryWhenArtifactMissing() throws Exception {
        stubFor(post(urlPathEqualTo("/api/v2/scanBinary"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"violations\":[]}")));

        Path classesDir = buildDirectory.resolve("classes");
        Files.createDirectories(classesDir);
        Files.write(classesDir.resolve("App.class"), new byte[]{0x01, 0x02, 0x03});

        Artifact mainArtifact = artifact("com.example", "demo-app", "1.0.0", Artifact.SCOPE_COMPILE, null);
        XrayScanMojo mojo = newMojo(mainArtifact, "archive-watch", true);

        mojo.execute();

        List<ServeEvent> events = wireMock.getAllServeEvents();
        assertThat(events).hasSize(1);
        JsonNode requestJson = MAPPER.readTree(events.get(0).getRequest().getBodyAsString());
        String filename = requestJson.path("filename").asText();
        assertThat(filename).endsWith(".zip");

        String base64Data = requestJson.path("data").asText();
        byte[] decoded = Base64.getDecoder().decode(base64Data);
        List<String> entries = new ArrayList<>();
        try (ZipInputStream zipInputStream = new ZipInputStream(new ByteArrayInputStream(decoded))) {
            ZipEntry entry;
            while ((entry = zipInputStream.getNextEntry()) != null) {
                entries.add(entry.getName());
            }
        }

        assertThat(entries).contains("classes/App.class");
    }

    @Test
    void shouldRaiseFailureWhenAuthenticationFails() throws Exception {
        stubFor(post(urlPathEqualTo("/api/v2/scanBinary"))
                .willReturn(aResponse().withStatus(401)));

        Path artifactFile = buildDirectory.resolve("demo-app-1.0.0.jar");
        Files.write(artifactFile, "binary".getBytes(StandardCharsets.UTF_8));

        Artifact mainArtifact = artifact("com.example", "demo-app", "1.0.0", Artifact.SCOPE_COMPILE, artifactFile);
        XrayScanMojo mojo = newMojo(mainArtifact, "default-watch", true);

        assertThatThrownBy(mojo::execute)
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("Authentification Xray");
    }

    private XrayScanMojo newMojo(Artifact mainArtifact, String watchName, boolean failOnThreshold, Artifact... dependencies) throws Exception {
        XrayScanMojo mojo = new XrayScanMojo();
        setField(mojo, "xrayUrl", wireMock.baseUrl() + "/api/v2");
        setField(mojo, "username", "user");
        setField(mojo, "password", "pass");
        setField(mojo, "watch", watchName);
        setField(mojo, "failOnThreshold", failOnThreshold);
        setField(mojo, "timeoutSeconds", 30);
        setField(mojo, "skip", false);

        MavenProject project = new MavenProject();
        Build build = new Build();
        build.setDirectory(buildDirectory.toString());
        project.setBuild(build);
        project.setArtifact(mainArtifact);

        LinkedHashSet<Artifact> artifactSet = new LinkedHashSet<>();
        if (dependencies != null && dependencies.length > 0) {
            artifactSet.addAll(Arrays.asList(dependencies));
        }
        if (mainArtifact != null) {
            artifactSet.add(mainArtifact);
        }
        project.setArtifacts(artifactSet);
        project.setDependencyArtifacts(artifactSet);

        setField(mojo, "project", project);
        return mojo;
    }

    private Artifact artifact(String groupId, String artifactId, String version, String scope, Path file) {
        DefaultArtifactHandler handler = new DefaultArtifactHandler("jar");
        DefaultArtifact artifact = new DefaultArtifact(groupId, artifactId,
                VersionRange.createFromVersion(version), scope, "jar", null, handler);
        artifact.setFile(file != null ? file.toFile() : null);
        return artifact;
    }

    private void setField(Object target, String fieldName, Object value) throws Exception {
        var field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }
}
