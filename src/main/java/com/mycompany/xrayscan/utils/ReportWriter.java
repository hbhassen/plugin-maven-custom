package com.mycompany.xrayscan.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.mycompany.xrayscan.model.CveResult;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Ecrit un rapport JSON des vulnérabilités détectées.
 */
public class ReportWriter {

    private final ObjectWriter writer;

    public ReportWriter() {
        ObjectMapper mapper = new ObjectMapper();
        this.writer = mapper.writerWithDefaultPrettyPrinter();
    }

    public void write(Path output, List<CveResult> results) throws IOException {
        Files.createDirectories(output.getParent());
        writer.writeValue(output.toFile(), results);
    }
}
