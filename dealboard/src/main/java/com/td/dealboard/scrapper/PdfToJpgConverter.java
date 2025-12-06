package com.td.dealboard.scrapper;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.rendering.PDFRenderer;

import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.stream.FileImageOutputStream;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.Iterator;

public class PdfToJpgConverter {

    public static void convertPdfToJpg(File pdfFile, String outputDir) throws IOException {
        PDDocument document = PDDocument.load(pdfFile);
        PDFRenderer pdfRenderer = new PDFRenderer(document);

        // Znajdź writer dla JPEG
        Iterator<ImageWriter> writers = ImageIO.getImageWritersByFormatName("jpg");
        if (!writers.hasNext()) {
            throw new IllegalStateException("No JPEG writers available");
        }
        ImageWriter writer = writers.next();

        for (int page = 0; page < document.getNumberOfPages(); page++) {
            BufferedImage bim = pdfRenderer.renderImageWithDPI(page, 300);

            String fileName = outputDir + File.separator + "CARR_page_" + (page + 1) + ".jpg";
            File outputFile = new File(fileName);

            ImageWriteParam params = writer.getDefaultWriteParam();
            if (params.canWriteCompressed()) {
                params.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);
                params.setCompressionQuality(0.9f); // 0.0 = najgorsza / 1.0 = najlepsza jakość
            }

            writer.setOutput(new FileImageOutputStream(outputFile));
            writer.write(null, new IIOImage(bim, null, null), params);
        }

        writer.dispose();
        document.close();
    }
}
