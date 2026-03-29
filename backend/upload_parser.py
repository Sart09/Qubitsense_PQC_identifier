"""
Utilities for parsing uploaded documents (Images and PDFs) 
to extract QR codes or Barcodes containing URLs/domains.
"""
import io
from PIL import Image
from pyzbar.pyzbar import decode
import fitz  # PyMuPDF

def extract_urls_from_image(image_bytes: bytes) -> list[str]:
    """Decodes QR or Barcodes from image bytes."""
    try:
        img = Image.open(io.BytesIO(image_bytes))
        decoded = decode(img)
        urls = [d.data.decode("utf-8") for d in decoded if d.data]
        return urls
    except Exception as e:
        print(f"[parser] Image extraction error: {e}")
        return []

def extract_urls_from_pdf(pdf_bytes: bytes) -> list[str]:
    """Decodes QR or Barcodes from PDF pages."""
    urls = []
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        for page_num in range(len(doc)):
            page = doc.load_page(page_num)
            pix = page.get_pixmap(matrix=fitz.Matrix(2, 2))  # upscale for better reading
            
            if pix.alpha:
                mode = "RGBA"
            else:
                mode = "RGB"
                
            img = Image.frombytes(mode, [pix.width, pix.height], pix.samples)
            decoded = decode(img)
            for d in decoded:
                if d.data:
                    urls.append(d.data.decode("utf-8"))
    except Exception as e:
        print(f"[parser] PDF extraction error: {e}")
    return urls

def parse_upload_for_urls(filename: str, file_bytes: bytes) -> list[str]:
    """Route the parsing logic based on file extension."""
    if filename.lower().endswith(".pdf"):
        return extract_urls_from_pdf(file_bytes)
    return extract_urls_from_image(file_bytes)
