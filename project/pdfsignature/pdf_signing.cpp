#include "pch.h"
#include "pdf_signing.h"

#include <cstddef>
#include <memory>
#include <type_traits>
#include <utility>

namespace std {
    template<class T> struct _Unique_if {
        typedef unique_ptr<T> _Single_object;
    };

    template<class T> struct _Unique_if<T[]> {
        typedef unique_ptr<T[]> _Unknown_bound;
    };

    template<class T, size_t N> struct _Unique_if<T[N]> {
        typedef void _Known_bound;
    };

    template<class T>
    typename _Unique_if<T>::_Unknown_bound
    make_unique(size_t n) {
        typedef typename remove_extent<T>::type U;
        return unique_ptr<T>(new U[n]());
    }
}

struct Annot {
    double fLeft;
    double fTop;
    char* text;
};

static double convert_to_pdf_units(const char* annot_units, double value)
{
    if (strcmp(annot_units, "mm") == 0)
    {
        return 72.0 * value / 25.4;
    }
    else if (strcmp(annot_units, "inch") == 0)
    {
        return 72.0 * value;
    }
    else
    {
        std::string err = "Unknown annotation unit '";
        err += annot_units;
        err += "'";

        PODOFO_RAISE_ERROR_INFO(ePdfError_InvalidEnumValue, err.c_str());
    }
}

void draw_annot(PdfDocument& document, PdfPainter& painter, const Annot& annot, const PdfRect& annot_rect) {
    const char* annot_units = "mm";
    double font_size = convert_to_pdf_units("mm", 5.0);
    PdfColor font_color(0.0, 0.0, 0.0);
    const char* font_name = "Helvetica";
    bool bUpdateFont = true;

    double fLeft = annot.fLeft;
    double fTop = annot.fTop;
    const char* text = annot.text;

    if (bUpdateFont)
    {
        PdfFont* pFont;

        pFont = document.CreateFont(font_name, false, false, false);
        if (!pFont)
        {
            std::string err = "Failed to create font '";
            err += font_name;
            err += "'";

            PODOFO_RAISE_ERROR_INFO(ePdfError_OutOfMemory, err.c_str());
        }

        pFont->SetFontSize((float)font_size);
        painter.SetFont(pFont);
        painter.SetColor(font_color);
    }

    fLeft = convert_to_pdf_units(annot_units, fLeft);
    fTop = convert_to_pdf_units(annot_units, fTop);

    painter.DrawMultiLineText(fLeft,
        0.0,
        annot_rect.GetWidth() - fLeft,
        annot_rect.GetHeight() - fTop,
        PdfString(reinterpret_cast<const pdf_utf8*>(text)));
}

static int print_errors_string(const char* str, size_t len, void* u)
{
    std::string* pstr = reinterpret_cast<std::string*>(u);

    if (!pstr || !len || !str)
        return 0;

    if (!pstr->empty() && (*pstr)[pstr->length() - 1] != '\n')
        *pstr += "\n";

    *pstr += std::string(str, len);

    // to continue
    return 1;
}

static void raise_podofo_error_with_opensslerror(const char* detail)
{
    std::string err;

    ERR_print_errors_cb(print_errors_string, &err);

    if (err.empty())
        err = "Unknown OpenSSL error";

    err = ": " + err;
    err = detail + err;

    PODOFO_RAISE_ERROR_INFO(ePdfError_InvalidHandle, err.c_str());
}

void sign_with_signer(PdfSignOutputDevice* signer, EVP_PKEY *pkey, X509* cert) {
    int len;
    auto buff = std::make_unique<char[]>(65565);
    char* out_buff = nullptr;
    long out_len;

    std::unique_ptr<BIO, std::function<void(BIO*)>> mem(
        BIO_new(BIO_s_mem()),
        [](BIO* ptr) { BIO_free(ptr); }
    );

    unsigned int flags = PKCS7_DETACHED | PKCS7_BINARY;
    std::unique_ptr<PKCS7, std::function<void(PKCS7*)>> pkcs7(
        PKCS7_sign(cert, pkey, nullptr, mem.get(), flags),
        [](PKCS7* ptr) { PKCS7_free(ptr); }
    );

    while ((len = signer->ReadForSignature(buff.get(), 65536)) > 0) {
        if (BIO_write(mem.get(), buff.get(), len) != len) {
            raise_podofo_error_with_opensslerror("Cannot sign certificate");
            return;
        }
    }

    if (PKCS7_final(pkcs7.get(), mem.get(), flags) <= 0) {
        raise_podofo_error_with_opensslerror("Cannot sign certificate");
        return;
    }

    bool success = false;
    std::unique_ptr<BIO, std::function<void(BIO*)>> out(
        BIO_new(BIO_s_mem()),
        [](BIO* ptr) { BIO_free(ptr); }
    );


    i2d_PKCS7_bio(out.get(), pkcs7.get());
    out_len = BIO_get_mem_data(out.get(), &out_buff);

    if (out_len > 0 && out_buff) {
        if (static_cast<size_t>(out_len) > signer->GetSignatureSize()) {
            std::ostringstream oss;
            oss << "Requires at least " << out_len << " bytes for the signature, but reserved is only " << signer->GetSignatureSize() << " bytes";
            PODOFO_RAISE_ERROR_INFO(ePdfError_ValueOutOfRange, oss.str().c_str());
            return;
        }

        PdfData signature(out_buff, out_len);
        signer->SetSignature(signature);
        success = true;
    }

    if (!success) {
        raise_podofo_error_with_opensslerror("Failed to get data from the output BIO");
        return;
    }
}

X509 *GenerateDerSignature(EVP_PKEY* pkey) {
    X509* x509 = nullptr;
    PdfPage* pPage = nullptr;

    /* Generate the certificate. */
    std::cout << "Generating x509 certificate..." << std::endl;

    bool check = CreateX509Cert(&x509, &pkey, 1, 365);
    if (!check) {
        raise_podofo_error_with_opensslerror("Cannot write to disk");
        return nullptr;
    }

    /* Write the private key and certificate out to disk. */
    std::cout << "Writing key and certificate to disk..." << std::endl;

    bool ret = write_to_disk(pkey, x509);
    if (!ret) {
        raise_podofo_error_with_opensslerror("Cannot write to disk");
        return nullptr;
    }
    std::cout << "Success write all the pem key" << std::endl;
    return x509;
}

static PdfObject* find_existing_signature_field(PdfAcroForm* pAcroForm, const PdfString& name)
{
    if (!pAcroForm)
        PODOFO_RAISE_ERROR(ePdfError_InvalidHandle);

    PdfObject* pFields = pAcroForm->GetObject()->GetDictionary().GetKey(PdfName("Fields"));
    if (pFields) {
        if (pFields->GetDataType() == ePdfDataType_Reference)
            pFields = pAcroForm->GetDocument()->GetObjects()->GetObject(pFields->GetReference());

        if (pFields && pFields->GetDataType() == ePdfDataType_Array) {
            PdfArray& rArray = pFields->GetArray();
            PdfArray::iterator it;
            PdfArray::iterator end = rArray.end();
            for (it = rArray.begin(); it != end; it++) {
                // require references in the Fields array
                if (it->GetDataType() == ePdfDataType_Reference) {
                    PdfObject* item = pAcroForm->GetDocument()->GetObjects()->GetObject(it->GetReference());

                    if (item && item->GetDictionary().HasKey(PdfName("T")) &&
                        item->GetDictionary().GetKey(PdfName("T"))->GetString() == name)
                    {
                        // found a field with the same name
                        const PdfObject* pFT = item->GetDictionary().GetKey(PdfName("FT"));
                        if (!pFT && item->GetDictionary().HasKey(PdfName("Parent"))) {
                            const PdfObject* pTemp = item->GetIndirectKey(PdfName("Parent"));
                            if (!pTemp) {
                                PODOFO_RAISE_ERROR(ePdfError_InvalidDataType);
                            }

                            pFT = pTemp->GetDictionary().GetKey(PdfName("FT"));
                        }

                        if (!pFT) {
                            PODOFO_RAISE_ERROR(ePdfError_NoObject);
                        }

                        const PdfName fieldType = pFT->GetName();
                        if (fieldType != PdfName("Sig")) {
                            std::string err = "Existing field '";
                            err += name.GetString();
                            err += "' isn't of a signature type, but '";
                            err += fieldType.GetName().c_str();
                            err += "' instead";

                            PODOFO_RAISE_ERROR_INFO(ePdfError_InvalidName, err.c_str());
                        }

                        return item;
                    }
                }
            }
        }
    }

    return NULL;
}

int SignPdf(std::string _input_file, std::string cert_file, std::string key_file, keytype key_type) {
    /*
    if (argc != 2)
    {
        printf("Usage: SignTest [output_filename]\n");
        printf("       - Create a PDF ready to be signed\n");
        return 0;
    }
    */

    // init and setup variable
    PdfSignatureField* pSignField = nullptr;
    PdfAnnotation* pTemporaryAnnot = nullptr; // for existing signature fields


    const char* certfile = nullptr;
    const char* pkeyfile = nullptr;
    const char* password = nullptr;
    const char* reason = "I agree";
    const char* sigsizestr = nullptr;
    const char* annot_units = "mm";
    const char* annot_position = "100.0,100.0,100.0,100.0";
    std::string input_file;
    std::string output_file;
    const char* field_name = "Kien's Signature";
    int annot_page = 0;
    double annot_left = 00, annot_top = 0, annot_width = 150.0, annot_height = 100.0;
    bool annot_print = true;
    bool field_use_existing = false;
    int result = 0;
    int pos = 0;

    input_file = std::move(_input_file);
    pos = input_file.find_last_of(".pdf");
    output_file = input_file.substr(0, pos-3);
    output_file += "-signed.pdf";
    std::cout << output_file << std::endl;

    try {
        PdfMemDocument document;
        PdfOutputDevice outputDevice(output_file.c_str());
        PdfSignOutputDevice signer(&outputDevice);
        PdfString name;
        PdfObject* pExistingSigField = nullptr;

        document.Load(input_file.c_str(), true);
        if (!document.GetPageCount())
            PODOFO_RAISE_ERROR_INFO(ePdfError_PageNotFound, "The document has no page. Only documents with at least one page can be signed");

        PdfAcroForm* pAcroForm = document.GetAcroForm();
        if (!pAcroForm)
            PODOFO_RAISE_ERROR_INFO(ePdfError_InvalidHandle, "acroForm == NULL");

        if (!pAcroForm->GetObject()->GetDictionary().HasKey(PdfName("SigFlags")) ||
            !pAcroForm->GetObject()->GetDictionary().GetKey(PdfName("SigFlags"))->IsNumber() ||
            pAcroForm->GetObject()->GetDictionary().GetKeyAsLong(PdfName("SigFlags")) != 3)
        {
            if (pAcroForm->GetObject()->GetDictionary().HasKey(PdfName("SigFlags")))
                pAcroForm->GetObject()->GetDictionary().RemoveKey(PdfName("SigFlags"));

            pdf_int64 val = 3;
            pAcroForm->GetObject()->GetDictionary().AddKey(PdfName("SigFlags"), PdfObject(val));
        }

        if (pAcroForm->GetNeedAppearances()) {
            pAcroForm->SetNeedAppearances(false);
        }

        
        if (field_name) {
            name = PdfString(field_name);

            pExistingSigField = find_existing_signature_field(pAcroForm, name);
            if (pExistingSigField && !field_use_existing)
            {
                std::string err = "Signature field named '";
                err += name.GetString();
                err += "' already exists";

                PODOFO_RAISE_ERROR_INFO(ePdfError_WrongDestinationType, err.c_str());
            }
        } else {
            char fldName[96]; // use bigger buffer to make sure sprintf does not overflow
            sprintf_s(fldName, "PodofoSignatureField");

            name = PdfString(fldName);
        }

        if (pExistingSigField)
        {
            if (!pExistingSigField->GetDictionary().HasKey("P"))
            {
                std::string err = "Signature field named '";
                err += name.GetString();
                err += "' doesn't have a page reference";

                PODOFO_RAISE_ERROR_INFO(ePdfError_PageNotFound, err.c_str());
            }

            PdfPage* pPage;
            pPage = document.GetPagesTree()->GetPage(pExistingSigField->GetDictionary().GetKey("P")->GetReference());
            if (!pPage)
                PODOFO_RAISE_ERROR(ePdfError_PageNotFound);

            pTemporaryAnnot = new PdfAnnotation(pExistingSigField, pPage);
            if (!pTemporaryAnnot)
                PODOFO_RAISE_ERROR_INFO(ePdfError_OutOfMemory, "Cannot allocate annotation object for existing signature field");

            pSignField = new PdfSignatureField(pTemporaryAnnot);
            if (!pSignField)
                PODOFO_RAISE_ERROR_INFO(ePdfError_OutOfMemory, "Cannot allocate existing signature field object");

            pSignField->EnsureSignatureObject();
        } else {
            PdfPage* pPage = document.GetPage(annot_page);
            if (!pPage)
                PODOFO_RAISE_ERROR(ePdfError_PageNotFound);

            PdfRect annot_rect;
            if (annot_position) {
                annot_rect = PdfRect(annot_left, pPage->GetPageSize().GetHeight() - annot_top - annot_height, annot_width, annot_height);
            }

            PdfAnnotation* pAnnot = pPage->CreateAnnotation(ePdfAnnotation_Widget, annot_rect);
            if (!pAnnot)
                PODOFO_RAISE_ERROR_INFO(ePdfError_OutOfMemory, "Cannot allocate annotation object");

            if (annot_position && annot_print)
                pAnnot->SetFlags(ePdfAnnotationFlags_Print);
            else if (!annot_position && (!field_name || !field_use_existing))
                pAnnot->SetFlags(ePdfAnnotationFlags_Invisible | ePdfAnnotationFlags_Hidden);

            pSignField = new PdfSignatureField(pAnnot, pAcroForm, &document);
            if (!pSignField)
                PODOFO_RAISE_ERROR_INFO(ePdfError_OutOfMemory, "Cannot allocate signature field object");

            if (annot_position) {
                PdfRect annotSize(0.0, 0.0, annot_rect.GetWidth(), annot_rect.GetHeight());
                PdfXObject sigXObject(annotSize, &document);
                PdfPainter painter;

                try {
                    painter.SetPage(&sigXObject);

                    /* Workaround Adobe's reader error 'Expected a dict object.' when the stream
                       contains only one object which does Save()/Restore() on its own, like
                       the image XObject. */
                    painter.Save();
                    painter.Restore();

                    Annot annot;
                    annot.fLeft = 10;
                    annot.fTop = 10;
                    annot.text = "Signed by Kien";
                    draw_annot(document, painter, annot, annot_rect);

                    pSignField->SetAppearanceStream(&sigXObject);
                }
                catch (PdfError& /*e*/)
                {
                    if (painter.GetPage())
                    {
                        try
                        {
                            painter.FinishPage();
                        }
                        catch (...)
                        {
                        }
                    }
                }

                painter.FinishPage();
            }
        }

        signer.SetSignatureSize(2048);

        pSignField->SetFieldName(name);
        pSignField->SetSignatureReason("I Agree");
        pSignField->SetSignatureDate(PdfDate());
        pSignField->SetSignature(*signer.GetSignatureBeacon());

        document.WriteUpdate(&signer, !output_file.empty());

        // Check if position of signature was found
        if (!signer.HasSignaturePosition())
            PODOFO_RAISE_ERROR_INFO(ePdfError_SignatureError, "Cannot find signature position in the document data");

        // Adjust ByteRange for signature
        signer.AdjustByteRange();

        // Read data for signature and count it
        // We have to seek at the beginning of the file
        signer.Seek(0);

        // Read data to be signed and send them to the
        // signature generator
        if (!cert_file.empty() && !key_file.empty()) {
            std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>> pkey(
                LoadKey(key_file.c_str()),
                [](EVP_PKEY* ptr) { EVP_PKEY_free(ptr); }
            );

            std::unique_ptr<X509, std::function<void(X509*)>> cert(
                LoadCert(cert_file.c_str()),
                [](X509* ptr) { X509_free(ptr); }
            );

            sign_with_signer(&signer, pkey.get(), cert.get());
            signer.Flush();
        }
        else {
            std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>> pkey(
                generatePubKey(2048, key_type),
                [](EVP_PKEY* ptr) { EVP_PKEY_free(ptr); }
            );

            std::unique_ptr<X509, std::function<void(X509*)>> cert(
                GenerateDerSignature(pkey.get()),
                [](X509* ptr) { X509_free(ptr); }
            );

            sign_with_signer(&signer, pkey.get(), cert.get());
            signer.Flush();
        }
    }
    catch (PdfError& e) {
        std::cerr << "Error: An error has ocurred." << std::endl;
        e.PrintErrorMsg();
        throw e.GetError();
        return 0;
    }
    return 0;
}