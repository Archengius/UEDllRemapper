#include <windows.h>
#include <dbghelp.h>
#include <limits.h>
#include <dirent.h>
#include "pelib/PeLib.h"
#include "CTypeInfoDump.h"
#include "CTypeInfoText.h"

struct SymbolInfo {
    std::string Name;
    ULONG64 Address;
    ULONG64 TypeId;
};

void checkPeLibError(int errorCode) {
    if (errorCode != PeLib::ERROR_NONE) {
        std::cerr << "Error when performing PeLib operation: " << errorCode << std::endl;
        std::cerr << "Last syscall error message: " << strerror(errno) << std::endl;
        exit(1);
    }
}

std::string getFunctionName(std::string& functionSignature) {
    ULONG64 pos = functionSignature.find('(');
    ULONG64 startPos = functionSignature.find_last_of(' ', pos) + 1;
    return functionSignature.substr(startPos, pos - startPos);
}

BOOL CALLBACK ProcessFunctionCallback(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, void* UserContext) {
    UNREFERENCED_PARAMETER(SymbolSize)
    auto* resultVec = static_cast<std::vector<SymbolInfo>*>(UserContext);
    SymbolInfo symbolInfo{};
    symbolInfo.Name = pSymInfo->Name;
    symbolInfo.Address = pSymInfo->Address;
    symbolInfo.TypeId = pSymInfo->TypeIndex;
    resultVec->push_back(symbolInfo);
    return false;
}

void replaceAll(std::string& input, const char* text, const char* replacement, ULONG64 limit = -1) {
    unsigned long long int pos;
    while ((pos = input.find(text)) != -1 && (limit == -1 || pos < limit)) {
        input.erase(pos, strlen(text));
        input.insert(pos, replacement);
    }
}

void removeExcessiveSpaces(std::string& input) {
    bool prev_is_space = true;
    input.erase(std::remove_if(input.begin(), input.end(), [&prev_is_space](unsigned char curr) {
        bool r = std::isspace(curr) && prev_is_space;
        prev_is_space = std::isspace(curr);
        return r;

    }), input.end());
}

std::string getTypeName(CTypeInfoText& infoText, ULONG64 typeId) {
    char symbolNameBuffer[MAX_SYM_NAME];
    infoText.GetTypeName(static_cast<ULONG>(typeId), nullptr, symbolNameBuffer, MAX_SYM_NAME);
    std::string resultString(symbolNameBuffer);
    if (resultString.find('<') != std::string::npos) {
        return "<GENERIC_TYPE>"; //TODO proper handling of generic types
    }
    replaceAll(resultString, "NEAR_C", "");
    removeExcessiveSpaces(resultString);
    return resultString;
}

std::string createFunctionName(SymbolInfo& symbolInfo, CTypeInfoText& infoText) {
    FunctionTypeInfo functionTypeInfo{};
    infoText.DumpObj()->DumpFunctionType(static_cast<ULONG>(symbolInfo.TypeId), functionTypeInfo);
    std::string& functionName = symbolInfo.Name;
    std::string resultString;
    if (functionTypeInfo.StaticFunction) {
        resultString.append("static ");
    } else if (functionTypeInfo.MemberFunction) {
        resultString.append("virtual ");
    }
    resultString.append(getTypeName(infoText, functionTypeInfo.RetTypeIndex));
    resultString.append(" ");
    resultString.append(functionName);
    resultString.append("(");

    for (int i = 0; i < functionTypeInfo.NumArgs; i++) {
        resultString.append(getTypeName(infoText, functionTypeInfo.Args[i]));
        resultString.append(",");
    }
    resultString.erase(resultString.length() - 1, 1);
    resultString.append(")");
    //just to match handling in case of formatFunctionName
    replaceAll(resultString, "<GENERIC_TYPE>,<GENERIC_TYPE>", "<GENERIC_TYPE>");
    return resultString;
}

ULONG64 findSymbolLocation(HANDLE hProcess, ULONG64 dllBase, CTypeInfoText& infoText, std::string& functionSignature) {
    if (functionSignature.find("::StaticConfigName") != std::string::npos) {
        //let's hope it will never get called
        //no idea why it is there actually
        return ULONG_LONG_MAX - 1;
    }
    std::vector<SymbolInfo> symbolInfo;
    std::string functionName = getFunctionName(functionSignature);
    SymEnumSymbols(hProcess, dllBase, functionName.c_str(), ProcessFunctionCallback, (void*) &symbolInfo);
    if (symbolInfo.empty()) {
        std::cout << "Symbol not found in executable for: " << functionName << std::endl;
        return ULONG_LONG_MAX;
    }
    if (symbolInfo.size() == 1) {
        //no need to iterate symbols and resolve types if there is only 1 symbol
        return symbolInfo[0].Address;
    }
    std::cout << "Multiple symbols (" << symbolInfo.size() << ") found for " << functionName << ", attempting signature match" << std::endl;
    for (auto &symbolInfo1 : symbolInfo) {
        std::string symbolSignature = createFunctionName(symbolInfo1, infoText);
        if (symbolSignature == functionSignature) {
            return symbolInfo1.Address;
        }
    }
    std::cout << "No matching symbol found in executable for: " << functionName << ". None of below matches: " << functionSignature << std::endl;
    for (auto &symbolInfo1 : symbolInfo) {
        std::string symbolSignature = createFunctionName(symbolInfo1, infoText);
        std::cout << "  " << symbolSignature << std::endl;
    }
    return ULONG_LONG_MAX;
}

void replaceGenericShit(std::string& functionName) {
    ULONG64 currentPos;
    while ((currentPos = functionName.find('?')) != std::string::npos) {
        auto startIndex = functionName.find_last_of(',', currentPos);
        if (startIndex == std::string::npos) startIndex = functionName.find('(');
        auto endIndex = functionName.find(',', currentPos);
        if (endIndex == std::string::npos) endIndex = functionName.find_last_of(')');
        //std::cout << functionName << " " << currentPos << " " << startIndex << " " << endIndex << std::endl;
        functionName.erase(startIndex + 1, endIndex - startIndex - 1);
        functionName.insert(startIndex + 1, "<GENERIC_TYPE>");
        //std::cout << functionName << " " << std::endl;
    }
}

void formatUndecoratedName(std::string& functionName) {
    removeExcessiveSpaces(functionName);
    replaceAll(functionName, "__int64", "int"); //replace int sizes
    replaceAll(functionName, "__ptr64", ""); //replace pointer markers
    replaceAll(functionName, "(void)", "()"); //replace (void) with empty arguments
    //access modifiers
    replaceAll(functionName, "public: ", "");
    replaceAll(functionName, "protected: ", "");
    replaceAll(functionName, "private: ", "");
    replaceAll(functionName, "const", ""); //const is meaningless in compiled code
    //remove function modifiers
    replaceAll(functionName, ")const", ")");
    //remove calling convention from functions
    replaceAll(functionName, "__cdecl", ""); //(default C/C++ calling convention)
    //remove type identifiers
    replaceAll(functionName, "class ", "");
    replaceAll(functionName, "union  ", "");
    replaceAll(functionName, "struct ", "");
    replaceAll(functionName, "enum ", "");
    //remove excessive spaces between type modifiers
    replaceAll(functionName, " *", "*");
    replaceAll(functionName, " &", "&");
    replaceAll(functionName, " )", ")");
    replaceAll(functionName, " ,", ",");
    replaceAll(functionName, "(*)()", "()*");
    //generic shit TODO find a nicer way of handling it
    replaceAll(functionName, "?? :: ??&", "<GENERIC_TYPE>", functionName.find('('));
    replaceGenericShit(functionName);
    replaceAll(functionName, "<GENERIC_TYPE>,<GENERIC_TYPE>", "<GENERIC_TYPE>");
    removeExcessiveSpaces(functionName);
}

ULONG64 findSymbolLocationDecorated(HANDLE hProcess, ULONG64 dllBase, CTypeInfoText& infoText, std::string& functionName) {
    char undecoratedName[MAX_SYM_NAME];
    UnDecorateSymbolName(functionName.c_str(), undecoratedName, MAX_SYM_NAME, 0);
    functionName.assign(undecoratedName);
    formatUndecoratedName(functionName);
    return findSymbolLocation(hProcess, dllBase, infoText, functionName);
}

int writeFunctionData(std::string& strFilename, ULONG64 offset, const char* payload, ULONG64 size) {
    std::fstream ofFile(strFilename.c_str(), std::ios_base::in);

    if (!ofFile) {
        ofFile.clear();
        ofFile.open(strFilename.c_str(), std::ios_base::out | std::ios_base::binary);
    } else {
        ofFile.close();
        ofFile.open(strFilename.c_str(), std::ios_base::in | std::ios_base::out | std::ios_base::binary);
    }

    if (!ofFile) {
        ofFile.clear();
        return PeLib::ERROR_OPENING_FILE;
    }
    ofFile.seekp(offset, std::ios::beg);
    ofFile.write(payload, size);
    ofFile.close();
    return PeLib::ERROR_NONE;
}

bool processModule(std::string& gameExecutableName,
        HANDLE hProcess, DWORD64 dllBase, CTypeInfoText& infoText,
        PeLib::ImportDirectory64& impDir, PeLib::dword stringAddr,
        std::unordered_map<std::string, ULONG64>& exportTable,
        std::vector<std::string>& unresolvedEntries) {
    bool patchedFileImportTable = false;

    for (uint32_t i = 0; i < impDir.getNumberOfFiles(PeLib::OLDDIR); i++) {
        auto fileName = impDir.getFileName(i, PeLib::OLDDIR);
        for (uint32_t j = 0; j < impDir.getNumberOfFunctions(i, PeLib::OLDDIR); j++) {
            auto functionName = impDir.getFunctionName(i, j, PeLib::OLDDIR);
            if (fileName.find("UE4") == 0 || fileName == gameExecutableName) {
                //add export entry to executable export table if it doesn't exist already
                if (exportTable.find(functionName) != exportTable.end()) continue;
                ULONG64 resultAddress = findSymbolLocationDecorated(hProcess, dllBase, infoText, functionName);
                if (resultAddress == ULONG_LONG_MAX){
                    unresolvedEntries.push_back(functionName);
                } else {
                    exportTable.insert({functionName, resultAddress});
                }
            }
        }
        //patch link executable name and mark file as patched
        if (fileName != gameExecutableName && fileName.find("UE4") == 0) {
            patchedFileImportTable = true;
            impDir.setRvaOfName(i, PeLib::OLDDIR, stringAddr);
        }
    }
    return patchedFileImportTable;
}

bool patchModule(std::string& targetModule, std::string& gameExecutableName, HANDLE hProcess, DWORD64 dllBase, CTypeInfoText& infoText, std::unordered_map<std::string, ULONG64>& exportTable) {
    unsigned int fileType = PeLib::getFileType(targetModule);
    if (fileType == PeLib::PEFILE_UNKNOWN) {
        std::cerr << "Cannot patch module " << targetModule << ": Invalid PE file." << std::endl;
        return false;
    }
    if (fileType != PeLib::PEFILE64) {
        std::cerr << "Cannot patch module " << targetModule << ": 32-bit executables not supported" << std::endl;
        return false;
    }
    auto* file = new PeLib::PeFile64(targetModule);
    file->readMzHeader();
    file->readPeHeader();
    file->readImportDirectory();

    auto& impDir = file->impDir();
    std::vector<std::string> unresolvedEntries;

    auto lastSecnr = static_cast<PeLib::word>(file->peHeader().calcNumberOfSections() - 1);
    auto importStrSize = static_cast<unsigned int>(gameExecutableName.size()) + 1;
    auto stringAddr = file->peHeader().getVirtualAddress(lastSecnr) + file->peHeader().getVirtualSize(lastSecnr);
    bool patchedFileImportTable = processModule(gameExecutableName, hProcess, dllBase, infoText, impDir, stringAddr, exportTable, unresolvedEntries);

    if (!unresolvedEntries.empty()) {
        std::cerr << "Cannot patch module " << targetModule << ". Missing symbols:" << std::endl;
        for (const std::string& string : unresolvedEntries) {
            std::cerr << "  " << string << std::endl;
        }
        delete file;
        return false;
    }
    if (patchedFileImportTable) {
        //probably a bad idea to just write data to last section
        file->peHeader().enlargeLastSection(importStrSize);
        checkPeLibError(writeFunctionData(targetModule, file->peHeader().rvaToOffset(stringAddr), gameExecutableName.c_str(), importStrSize));
        PeLib::dword impDirRva = file->peHeader().getIddImportRva();
        checkPeLibError(file->peHeader().write(targetModule, file->mzHeader().getAddressOfPeHeader()));
        checkPeLibError(impDir.write(targetModule, static_cast<unsigned int>(file->peHeader().rvaToOffset(impDirRva)), impDirRva));
        std::cout << "Successfully patched module " << targetModule << std::endl;
    }
    delete file;
    return true;
}

bool processGameExecutable(std::string& gameExecutable, std::unordered_map<std::string, ULONG64>& exportTable) {
    std::string gameExecutableName = gameExecutable.substr(gameExecutable.find_last_of('\\') + 1);
    unsigned int fileType = PeLib::getFileType(gameExecutable);
    if (fileType == PeLib::PEFILE_UNKNOWN) {
        std::cerr << "Cannot patch game executable " << gameExecutableName << ": Invalid PE file." << std::endl;
        return false;
    }
    if (fileType != PeLib::PEFILE64) {
        std::cerr << "Cannot patch game executable " << gameExecutableName << ": 32-bit executables not supported" << std::endl;
        return false;
    }
    auto* file = new PeLib::PeFile64(gameExecutable);
    file->readMzHeader();
    file->readPeHeader();
    file->readExportDirectory();

    auto sectionIndex = static_cast<PeLib::word>(file->peHeader().calcNumberOfSections() - 1);
    PeLib::dword exportRVA = file->peHeader().getIddExportRva();
    PeLib::ExportDirectory exportDir = file->expDir();
    bool changedFile = false;
    bool shouldWriteSections = false;
    std::cout << "Export RVA: " << exportRVA << " Section " << file->peHeader().getSectionWithRva(exportRVA) << std::endl;
    if (file->peHeader().getSectionWithRva(exportRVA) != sectionIndex ||
        file->peHeader().getSectionName(sectionIndex) != ".exports") {
        sectionIndex++;
        file->peHeader().addSection(".exports", exportDir.size());
        file->peHeader().makeValid(file->mzHeader().getAddressOfPeHeader());
        exportRVA = file->peHeader().getVirtualAddress(sectionIndex);
        file->peHeader().setIddExportRva(exportRVA);
        file->peHeader().setIddExportSize(exportDir.size());
        std::cout << "New Export RVA " << exportRVA << " at " << sectionIndex << std::endl;
        std::cout << "Migrating Export Table to last section... " << gameExecutable << std::endl;
        shouldWriteSections = true;
        changedFile = true;
    }

    if (exportDir.getNameString() != gameExecutableName) {
        std::cout << "Game executable name in ExportSection doesn't match provided one, renaming (from " << exportDir.getNameString() << " to " << gameExecutableName << ")" << std::endl;
        exportDir.setNameString(gameExecutableName);
        changedFile = true;
    }

    for (std::pair<std::string, ULONG64> pair : exportTable) {
        if (exportDir.getFunctionIndex(pair.first) == -1) {
            PeLib::dword index = exportDir.getNumberOfFunctions();
            exportDir.addFunction(pair.first, static_cast<PeLib::dword>(pair.second));
            exportDir.setFunctionOrdinal(index, static_cast<PeLib::word>(exportDir.getBase() + index));
            changedFile = true;
        }
    }

    if (file->peHeader().getIddExportSize() != exportDir.size()) {
        std::cout << "Adjusting export directory size in executable header" << std::endl;
        file->peHeader().setIddExportSize(exportDir.size());
        changedFile = true;
    }

    PeLib::dword sectionSize = file->peHeader().getSizeOfRawData(sectionIndex);
    if (exportDir.size() > sectionSize) {
        file->peHeader().enlargeLastSection(exportDir.size() - sectionSize);
        std::cout << "Expanding exports section: old size was " << sectionSize << ", required one is " << exportDir.size() << std::endl;
        changedFile = true;
    }

    if (changedFile) {
        if (shouldWriteSections) checkPeLibError(file->peHeader().writeSections(gameExecutable));
        checkPeLibError(file->peHeader().write(gameExecutable, file->mzHeader().getAddressOfPeHeader()));
        checkPeLibError(exportDir.write(gameExecutable, static_cast<unsigned int>(file->peHeader().rvaToOffset(exportRVA)), exportRVA));
        std::cout << "Updated game executable exports table " << gameExecutableName << std::endl;
    }
    delete file;
    return true;
}

int main() {
    std::string gameExecutable(R"(D:\SatisfactoryEarlyAccess\FactoryGame\Binaries\Win64\FactoryGame-Win64-Shipping.exe)");
    std::string moduleListFolder(R"(D:\SatisfactoryEarlyAccess\FactoryGame\Binaries\Win64\Mods)");
    std::string gameExecutableName = gameExecutable.substr(gameExecutable.find_last_of('\\') + 1);

    HANDLE hProcess = GetCurrentProcess();
    if (SymInitialize(hProcess, nullptr, FALSE) == FALSE) {
        return 1;
    }
    DWORD64 baseOfDll = SymLoadModuleEx(hProcess, nullptr, gameExecutable.c_str(), nullptr, 0, 0, nullptr, 0);
    if (baseOfDll == 0) {
        SymCleanup(hProcess);
        return 1;
    }
    CTypeInfoDump typeInfoDump(hProcess, baseOfDll);
    CTypeInfoText infoText(&typeInfoDump);
    std::unordered_map<std::string, ULONG64> exportTable;

    DIR *dir;
    struct dirent *ent;
    //should use std::filesystem::directory_iterator, but it throws compilation error on inclusion for some reason on mingw
    if ((dir = opendir (moduleListFolder.c_str())) != nullptr) {
        while ((ent = readdir (dir)) != nullptr) {
            std::string moduleName(ent->d_name);
            if (moduleName.find_last_not_of(".dll") != std::string::npos) {
                std::string modulePath(moduleListFolder);
                modulePath.append("\\");
                modulePath.append(moduleName);
                std::cout << "Attempting to scan module " << modulePath << std::endl;
                patchModule(modulePath, gameExecutableName, hProcess, baseOfDll, infoText, exportTable);
            }
        }
        closedir (dir);
    } else {
        std::cerr << "Cannot open mod directory " << moduleListFolder << std::endl;
        return 1;
    }
    processGameExecutable(gameExecutable, exportTable);
    SymCleanup(hProcess);
    return 0;
}