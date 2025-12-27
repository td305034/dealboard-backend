package com.td.dealboard.scrapper;

public class PdfResult {

    public final String fileName;
    public final boolean ok;
    public final int count;
    public final String error;

    private PdfResult(String fileName, boolean ok, int count, String error) {
        this.fileName = fileName;
        this.ok = ok;
        this.count = count;
        this.error = error;
    }

    public static PdfResult ok(String fileName, int count) {
        return new PdfResult(fileName, true, count, null);
    }

    public static PdfResult failed(String fileName, String error) {
        return new PdfResult(fileName, false, 0, error);
    }

    @Override
    public String toString() {
        return "FileResult{" +
                "fileName='" + fileName + '\'' +
                ", ok=" + ok +
                ", count=" + count +
                ", error='" + error + '\'' +
                '}';
    }
}
