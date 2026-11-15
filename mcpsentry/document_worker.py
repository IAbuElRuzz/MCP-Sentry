"""Standalone isolated Python worker. Never executed with document-supplied code."""

import io
import json
import resource
import sys
import xml.etree.ElementTree as ET
import zipfile

LIMIT = 1_048_576
TEXT_LIMIT = 131072


def office(raw):
    texts, complete = [], True
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        names = {e.filename for e in entries}
        if "[Content_Types].xml" not in names or not names.intersection({"word/document.xml", "xl/workbook.xml", "ppt/presentation.xml"}):
            raise ValueError("invalid_office_package")
        if len(entries) > 128 or sum(e.file_size for e in entries) > 4 * LIMIT:
            raise ValueError("document_expansion_limit")
        texts.append(archive.comment.decode("utf-8", errors="replace"))
        for entry in entries:
            texts.extend([entry.filename, entry.comment.decode("utf-8", errors="replace")])
            texts.append(entry.extra.decode("utf-8", errors="ignore"))
            if entry.is_dir():
                continue
            if not entry.filename.endswith((".xml", ".rels", ".txt")):
                complete = False  # Images, macros, OLE, and embedded files need more analysis.
                continue
            with archive.open(entry) as stream:
                content = stream.read(LIMIT + 1)
            if len(content) > LIMIT:
                raise ValueError("document_part_limit")
            if b"<!DOCTYPE" in content.upper() or b"<!ENTITY" in content.upper():
                raise ValueError("document_entities_forbidden")
            if entry.filename.endswith(".txt"):
                texts.append(content.decode("utf-8"))
                continue
            # Reject UTF-16 XML rather than allow an encoded DTD to evade the
            # byte-level entity check; typical OOXML parts are UTF-8.
            if b"\x00" in content:
                raise ValueError("document_xml_encoding_unsupported")
            root = ET.fromstring(content)
            texts.append("".join(root.itertext()))  # Reassemble split Word/slide text runs.
            texts.extend(str(value) for node in root.iter() for value in node.attrib.values())
            if b"macroEnabled" in content or b"vbaProject" in content:
                complete = False
    return texts, complete


def pdf_pypdf(raw):
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(raw), strict=True)
    if reader.is_encrypted:
        return [], False
    if len(reader.pages) > 32:
        raise ValueError("document_page_limit")
    texts, complete = [], True
    root = reader.trailer["/Root"]
    if any(key in root for key in ("/OpenAction", "/AA", "/AcroForm", "/Names", "/Outlines", "/Collection")) or reader.attachments:
        complete = False
    if "/Metadata" in root:
        content = root["/Metadata"].get_object().get_data()
        if len(content) > LIMIT or b"\x00" in content or b"<!DOCTYPE" in content.upper() or b"<!ENTITY" in content.upper():
            complete = False
        else:
            metadata = ET.fromstring(content)
            texts.append("".join(metadata.itertext()))
            texts.extend(v for node in metadata.iter() for v in node.attrib.values())
    if reader.metadata:
        texts.extend(str(v) for v in reader.metadata.values())
    for page in reader.pages:
        if page.get("/Annots") or page.images:
            complete = False
        content = page.get_contents()
        if content is not None and len(content.get_data()) > LIMIT:
            raise ValueError("document_page_content_limit")
        text = page.extract_text() or ""
        if not text.strip():
            complete = False  # Scanned/image-only pages require OCR.
        texts.append(text)
    return texts, complete


def pdf_pdfminer(raw):
    from pdfminer.converter import TextConverter
    from pdfminer.layout import LAParams
    from pdfminer.pdfdocument import PDFDocument
    from pdfminer.pdfinterp import PDFPageInterpreter, PDFResourceManager
    from pdfminer.pdfpage import PDFPage
    from pdfminer.pdfparser import PDFParser
    from pdfminer.pdftypes import resolve1
    from pdfminer.utils import decode_text
    document = PDFDocument(PDFParser(io.BytesIO(raw)))
    if document.encryption or not document.is_extractable:
        return [], False
    complete = not any(k in document.catalog for k in ("OpenAction", "AA", "AcroForm", "Names", "Outlines", "Collection"))
    texts = []
    for info in document.info:
        texts.extend(decode_text(value) if isinstance(value, bytes) else str(value) for value in info.values())
    metadata = resolve1(document.catalog.get("Metadata"))
    if metadata is not None:
        content = metadata.get_data()
        if len(content) > LIMIT or b"\x00" in content or b"<!DOCTYPE" in content.upper() or b"<!ENTITY" in content.upper():
            complete = False
        else:
            xml = ET.fromstring(content)
            texts.append("".join(xml.itertext()))
            texts.extend(v for node in xml.iter() for v in node.attrib.values())
    manager, count = PDFResourceManager(), 0
    for index, page in enumerate(PDFPage.create_pages(document)):
        if index >= 32:
            raise ValueError("document_page_limit")
        count += 1
        # Form XObjects may contain images or other uninspected graphics. Stay
        # conservative rather than treating their text extraction as complete.
        if page.annots or resolve1(page.resources.get("XObject", {})):
            complete = False
        for stream in page.contents:
            content = stream.get_data()
            if len(content) > LIMIT:
                raise ValueError("document_page_content_limit")
            if b" BI" in content or content.startswith(b"BI"):
                complete = False
            texts.append(content.decode("utf-8", errors="ignore"))
        output = io.StringIO()
        with TextConverter(manager, output, laparams=LAParams()) as device:
            PDFPageInterpreter(manager, device).process_page(page)
            text = output.getvalue()
        if not text.strip():
            complete = False
        texts.append(text)
    return texts, complete and count > 0


def pdf(raw):
    try:
        import pypdf
    except ImportError:
        return pdf_pdfminer(raw)
    return pdf_pypdf(raw)


def main():
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
        # macOS reserves a large shared-cache address range and rejects a small
        # RLIMIT_AS. Bound its data segment; Linux uses a whole-address limit.
        memory_resource = resource.RLIMIT_DATA if sys.platform == "darwin" else resource.RLIMIT_AS
        try:
            resource.setrlimit(memory_resource, (384 * LIMIT, 384 * LIMIT))
        except (ValueError, OSError):
            if sys.platform != "darwin":
                raise
            # macOS may reject both AS and DATA limits. The parent then bounds
            # wall time and polls RSS; this is not a hard kernel memory limit.
        resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
        raw = sys.stdin.buffer.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ValueError("document_too_large")
        texts, complete = pdf(raw) if sys.argv[1] == "pdf" else office(raw)
        if len(texts) > 4096 or sum(map(len, texts)) > TEXT_LIMIT:
            raise ValueError("document_text_limit")
        result = {"texts": texts, "complete": complete, "issue": "" if complete else "document_incomplete"}
    except ImportError:
        result = {"texts": [], "complete": False, "issue": "document_dependency_missing"}
    except BaseException:
        result = {"texts": [], "complete": False, "issue": "document_parser_failure"}
    sys.stdout.write(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
