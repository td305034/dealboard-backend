package com.td.dealboard.scrapper;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Paths;
import java.util.stream.Collectors;

public class PythonRunner {

    public static String runPython(String path) throws Exception {

        ProcessBuilder pb = new ProcessBuilder(
                "python",
                "agent_runner/agent_runner.py",
                path
        );

        pb.redirectErrorStream(false);  // łączy stderr ze stdout

        Process process = pb.start();

//        // wczytaj cały stdout
//        String result;
//        try (BufferedReader reader = new BufferedReader(
//                new InputStreamReader(process.getInputStream())
//        )) {
//            result = reader.lines().collect(Collectors.joining());
//        }
//
//        int exitCode = process.waitFor();
//        if (exitCode != 0) {
//            throw new RuntimeException("Python script failed: " + exitCode);
//        }
//
//        return result; // tutaj JSON

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
