package com.td.dealboard.scrapper;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class PythonRunner {
    public static String runPython(String script, List<String> paths) throws Exception {

        List<String> command = new ArrayList<>();
        command.add("python");
        command.add("ai_runner/" + script + ".py");

        paths.forEach(command::add);

        ProcessBuilder pb = new ProcessBuilder(command);

        pb.redirectErrorStream(false);

        Process process = pb.start();

        try (BufferedReader outReader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
             BufferedReader errReader = new BufferedReader(
                     new InputStreamReader(process.getErrorStream()))) {

            String stdout = outReader.lines().collect(Collectors.joining("\n"));
            String stderr = errReader.lines().collect(Collectors.joining("\n"));

            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new RuntimeException(
                        "Python script failed: " + exitCode + "\nSTDOUT:\n" + stdout + "\nSTDERR:\n" + stderr
                );
            }

            return stdout;
        }
    }
}
