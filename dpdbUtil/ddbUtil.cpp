// dpdbUtil.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <shlwapi.h>
#include <wchar.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <iostream>
#include <filesystem>
#include <vector>
#include <fstream>
#include <stdexcept>
#include "DriverPackMgr.h"

namespace fs=std::filesystem;

void usage();



wchar_t selfPathFull[MAX_PATH];
wchar_t selfPath[MAX_PATH];
wchar_t selfName[MAX_PATH];
//const wchar_t *selfName;

int wmain(int argc,wchar_t* argv[]){
    GetModuleFileNameW(nullptr,selfPathFull,MAX_PATH);
    wcscpy_s(selfPath,MAX_PATH,selfPathFull);
    PathRemoveFileSpecW(selfPath);
    const wchar_t* selfNameBuf;
    selfNameBuf=PathFindFileNameW(selfPathFull);
    wcscpy_s(selfName,MAX_PATH,selfNameBuf);
    if(argc<2){
        usage();
        return 1;
    }
    std::wstring argA=argv[1];
    std::wstring argB=argv[2];
    std::wstring ddbPath;
    std::wprintf(L"%s\n%s\n",argA.c_str(),argB.c_str());
    ddb db;
    
    if(fs::is_directory(argA)){
        std::wstring drvPath=argA;
        ddbPath=argB;
        std::vector<vecBuf> fList;
        wchar_t fPathRel[MAX_PATH];
        wchar_t fPathCon[MAX_PATH];
        for(const auto& entry:fs::recursive_directory_iterator(drvPath)){
            if(entry.is_regular_file()&&entry.path().extension()==L".inf"){
                vecBuf f;
                //BOOL PathRelativePathToW(
                //    [out] LPWSTR  pszPath,
                //    [in]  LPCWSTR pszFrom,
                //    [in]  DWORD   dwAttrFrom,
                //    [in]  LPCWSTR pszTo,
                //    [in]  DWORD   dwAttrTo
                //);
                std::wstring fPathFull=entry.path().wstring();
                PathRelativePathToW(fPathRel,drvPath.c_str(),FILE_ATTRIBUTE_DIRECTORY,fPathFull.c_str(),FILE_ATTRIBUTE_NORMAL);
                PathCanonicalizeW(fPathCon,fPathRel);
                f.fPath=std::wstring(fPathCon);
                std::wprintf(L"Reading: \"%s\"\n",fPathFull.c_str());
                std::ifstream file(fPathFull,std::ios::binary);
                if(!file){
                    std::wprintf(L"Error: Unable to open \"%s\" for reading.\n",fPathFull.c_str());
                    continue;
                }
                file.seekg(0,std::ios::end);
                std::streamsize fSize=file.tellg();
                file.seekg(0,std::ios::beg);
                if(fSize==-1){
                    std::wprintf(L"Error: unable to get file size of \"%s\"\n",fPathFull.c_str());
                    continue;
                }
                std::string file_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                //size_t fOffs=0;
                //size_t fLenW = (fSize - fOffs) / sizeof(wchar_t);
                //f.fData = std::wstring(fLenW, L'\0');
                //file.read(reinterpret_cast<char*>(&f.fData[0]), fLenW * sizeof(wchar_t));
                //if (!file) {
                //  std::wprintf(L"Error: Unable to read file contents of \"%s\".\n", fPathFull.c_str());
                //  continue;
                //}
                //file.seekg(0, std::ios::beg);
                //char bomdat[4];
                //file.read(bomdat,4);
                uint8_t bom = check_bom(file_data.c_str(), file_data.size());
                if (bom) {
                  if (bom == 4) { // UTF16-LE
                    f.fData = ConvertUtf16LeBufferToWString(file_data.c_str(), file_data.size());
                    //f.fData = convu16le.from_bytes(
                    //  reinterpret_cast<const char*> (&file_data[0]),
                    //  reinterpret_cast<const char*> (&file_data[0] + file_data.size()));
                    if (f.fData.at(0) == L'\xFEFF') {
                      f.fData.replace(0, 1, L" ");
                    }
                    f.fData.shrink_to_fit();
                  }
                  else if (bom == 1) {
                    f.fData = s2ws(file_data.c_str() + 3);
                  }
                  else {
                    std::wprintf(L"Unhandled BOM!");
                    continue;
                  }
                } else {
                  f.fData = s2ws(file_data);
                }
                fList.push_back(f);
            }
        }
        // Parse Drivers
        std::wprintf(L"[Parsing INFs]\n");
        db.dbMagic=L"~!Infinity.DriverDB";
        db.dbSpec=1;

        dpmGenDDB(db,fList);
        try{
            dpmWriteDDB(db,ddbPath);
        } catch(const std::exception& e){
            // print the exception
            std::wprintf(L"Exception while writing DriverDB \"%s\": %s\n",ddbPath.c_str(),e.what());
            return 1;
        }
        return 0;
    } else if(fs::is_regular_file(argA)){
        ddbPath=argA;
        std::wprintf(L"Reading \"%s\"...",ddbPath.c_str());
        try{
            dpmReadDDB(db,ddbPath);
        } catch (const std::exception &e) {
                // print the exception
                std::wprintf(L"Exception while reading DriverDB \"%s\": %s\n",ddbPath.c_str(),e.what());
                return 1;
        }
        uint32_t idrvc=db.dbDrivers.size();
        uint32_t idevc=db.dbDevices.size();
        wprintf(L"Done (Found: %d %s, %d %s)\n\n",idrvc,idrvc!=1?L"drivers":L"driver",idevc,idevc!=1?L"devices":L"device");

        std::vector<devInfo> sysDevs;
        dpmGetSysDevs(sysDevs);
        std::vector<std::wstring> devMatches;
        dpmMatchDevs(sysDevs,db,devMatches);
        if(argB==L"-list"){
            std::wprintf(L"[Matches]\n");
            for(auto&& y:devMatches){
                std::wprintf(L"%s\n",y.c_str());
            }
        //} else if(argB==L"-list"){
        //    std::wprintf(L"[Matches]\n");
        //    for(auto&& y:devMatches){
        //        std::wprintf(L"%s\n",y.c_str());
        //    }
        //} else if(argB==L"-drvload"){
        } else {
            usage();
            return 1;
        }
    } else{
        usage();
        return 1;
    }
}

void usage(){
    std::wprintf(L"Usage:\n[Generate DB]\n%s <DriverPath> <Dest.ddb>\n\n[Scan DB]\n%s <Path.ddb> (-list|-drvload)\n\n",selfName,selfName);
}


// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
