#pragma once
#include "GenKey.h"
#include "base64.h"

#define _SILENCE_CXX17_ITERATOR_BASE_CLASS_DEPRECATION_WARNING
#define _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS

//#include "NSSSignatureGenerator.h"

//#include <cert.h>
//#include <certt.h>

#include <iostream>
#include <functional>
#include <cstdio>
#include <stdexcept>
#include <Windows.h>
#include <openssl/bio.h>
#include <string>

using namespace PoDoFo;
int SignPdf(std::string _input_file, std::string cert_file, std::string key_file, keytype key_type);
