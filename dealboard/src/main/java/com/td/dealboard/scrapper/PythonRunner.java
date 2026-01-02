package com.td.dealboard.scrapper;

import com.td.dealboard.leaflet.Leaflet;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;

public class PythonRunner {

//    public static void runForLeaflets(List<Leaflet> leaflets){
//        for(Leaflet l : leaflets) {
//            List<String> paths = l.getPages();
//            for (String p : paths) {
//                try {
//                    String path = Paths.get("leaflets", p).toString();
//                    String result = runPython("ai_runner", p);
//                    System.out.println("Result for leaflet page " + p + ": " + result);
//                } catch (Exception e) {
//                    System.out.println("Error processing leaflet: " + l.getUrl());
//                    e.printStackTrace();
//                }
//            }
//        }
//    }
    public static String runPython(String script, String path) throws Exception {

        ProcessBuilder pb = new ProcessBuilder(
                "python",
                "ai_runner/" + script + ".py",
                path
        );

        pb.redirectErrorStream(false);  // łączy stderr ze stdout

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
