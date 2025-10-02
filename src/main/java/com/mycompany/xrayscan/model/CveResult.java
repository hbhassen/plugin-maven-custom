package com.mycompany.xrayscan.model;

import java.util.Objects;

/**
 * Représentation d'une vulnérabilité retournée par JFrog Xray.
 */
public class CveResult {

    private final String cveId;
    private final String packageName;
    private final String version;
    private final double cvssScore;
    private final String severity;
    private final String summary;

    public CveResult(String cveId, String packageName, String version, double cvssScore, String severity, String summary) {
        this.cveId = cveId != null ? cveId : "";
        this.packageName = packageName != null ? packageName : "";
        this.version = version != null ? version : "";
        this.cvssScore = cvssScore;
        this.severity = severity != null ? severity : "";
        this.summary = summary != null ? summary : "";
    }

    public String getCveId() {
        return cveId;
    }

    public String getPackageName() {
        return packageName;
    }

    public String getVersion() {
        return version;
    }

    public double getCvssScore() {
        return cvssScore;
    }

    public String getSeverity() {
        return severity;
    }

    public String getSummary() {
        return summary;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CveResult)) return false;
        CveResult cveResult = (CveResult) o;
        return Double.compare(cveResult.cvssScore, cvssScore) == 0
                && Objects.equals(cveId, cveResult.cveId)
                && Objects.equals(packageName, cveResult.packageName)
                && Objects.equals(version, cveResult.version)
                && Objects.equals(severity, cveResult.severity)
                && Objects.equals(summary, cveResult.summary);
    }

    @Override
    public int hashCode() {
        return Objects.hash(cveId, packageName, version, cvssScore, severity, summary);
    }

    @Override
    public String toString() {
        return "CveResult{" +
                "cveId='" + cveId + '\'' +
                ", packageName='" + packageName + '\'' +
                ", version='" + version + '\'' +
                ", cvssScore=" + cvssScore +
                ", severity='" + severity + '\'' +
                ", summary='" + summary + '\'' +
                '}';
    }
}
