#include <Windows.h>
#include <assert.h>
#include <devguid.h>
#include <devpkey.h>
#include <io.h>
#include <regstr.h>
#include <setupapi.h>
#include <stdio.h>
#include <time.h>

#include <cctype>
#include <chrono>
#include <codecvt>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <locale>
#include <regex>
#include <sstream>
#include <string>
#include <algorithm>
#include <cwctype>

#include "DriverPackMgr.h"
#include "dpmCommon.h"

extern int dpmMain(){
    if(localDPs.size()>0){
        tPerf dpPerfTot(L"dpTotal");
        tPerf dpPerfArc(L"dpArchive");
        dpPerfTot.start();
        for(std::size_t i=0; i<localDPs.size(); ++i){
            std::wprintf(L"(%llu\\%llu): %s\r\n",(uint64_t)i,localDPs.size(),localDPs[i].dpFileName.c_str());
            auto dbFname=(std::wstring(dpsPath)+L"\\"+localDPs[i].dpBaseName+L".ddb");
            if(_waccess(dbFname.c_str(),0)!=0){
                dpPerfArc.start();
                std::wprintf(L"Extracting %s Driver INFs...",localDPs[i].dpFileName.c_str());
                //dpGetInfs(localDPs[i]);
                std::wprintf(L"done\r\n");
                dpPerfArc.chkpt();
                wprintf(L"Inf Extract time: %0.4fms\r\n\r\n",dpPerfArc.tLast);
                std::wprintf(L"Generating %s Driver Database...\r\n",localDPs[i].dpFileName.c_str());
                dpGenDB(localDPs[i]);
                std::wprintf(L"Generating %s Driver Database...done\r\n",localDPs[i].dpFileName.c_str());
            } else{
                std::wprintf(L"Loading %s Driver Database...",localDPs[i].dpFileName.c_str());
                dpGetDB(localDPs[i]);
                std::wprintf(L"done\r\n");
            }
            std::wprintf(L"[%ls,%u,%ls,%d,%ls,%llu,%llu,%llu]\r\n\r\n",
                         localDPs[i].dpDB.dbMagic.c_str(),localDPs[i].dpDB.dbSpec,
                         localDPs[i].dpDB.dpBaseName.c_str(),
                         localDPs[i].dpDB.dpVersion,
                         localDPs[i].dpDB.dpFileName.c_str(),
                         localDPs[i].dpDB.dbDevices.size(),
                         localDPs[i].dpDB.dbStrings.size(),
                         localDPs[i].dpDB.dbDrivers.size());
            // return 0;
        }
        dpPerfTot.chkpt(true);
        std::wprintf(L"Total time: %0.4fms\r\n\r\n",dpPerfTot.tLast);
    }

    //  Get System Devices
    std::vector<devInfo> sysDevs;
    dpmGetSysDevs(sysDevs);


    // Extract Drivers
    return 0;
}

// Ref: https://stackoverflow.com/a/4130267
const wchar_t* WinGetEnv(const wchar_t* name){
    const DWORD buffSize=65535;
    static wchar_t buffer[buffSize];
    if(GetEnvironmentVariableW(name,buffer,buffSize)){
        return buffer;
    } else{
        return 0;
    }
}

// Ref: Gemini 2.5 Pro
std::wstring GetNativeProcessorArchitectureString(){
    SYSTEM_INFO sysInfo;
    GetNativeSystemInfo(&sysInfo); // This gets the true hardware architecture

    switch(sysInfo.wProcessorArchitecture){
    case PROCESSOR_ARCHITECTURE_AMD64:
        return L"ntamd64"; // x64
    case PROCESSOR_ARCHITECTURE_ARM:
        return L"ntarm";
    case PROCESSOR_ARCHITECTURE_ARM64:
        return L"ntarm64";
    case PROCESSOR_ARCHITECTURE_IA64: // Itanium (rare now)
        return L"ntia64";
    case PROCESSOR_ARCHITECTURE_INTEL: // x86
        return L"ntx86";
    case PROCESSOR_ARCHITECTURE_UNKNOWN:
    default:
        return L"unknown";
    }
}

bool dpmMatchDevs(std::vector<devInfo> &sysDevs, ddb &db,std::vector<std::wstring>& matchList){
    std::vector<std::wstring>::iterator it;
    bool drvMatch;
    bool hasArch;
    bool hasDev;
    bool dateNew;
    bool verNew;
    bool bCapt=1;
    uint32_t iDev=0;
    std::vector<devMatch> devMatches;

    // Organize HWIDs/CompatIDs by priority.
    while(bCapt){
        bCapt=0;
        for(uint32_t z=0; z<sysDevs.size(); z++){
            std::vector<std::wstring> devIds=sysDevs[z].hwids;
            if(!devIds.size()) continue;
            if(iDev>devIds.size()-1) continue;
            hasDev=0;
            for(auto&& y:devMatches){
                if(y.devId!=devIds[iDev]) continue;
                hasDev=1;
                y.iDevs.push_back(z);
                break;
                bCapt=1;
            }
            if(hasDev) continue;
            devMatch dr;
            dr.iDevs.push_back(z);
            // dr.iDev = z;
            dr.devId=devIds[iDev];
            devMatches.push_back(dr);
            bCapt=1;
        }
        iDev++;
    }

    iDev=0;
    hasDev=0;
    bCapt=0;
    // Get DP drivers for local devices.
    uint32_t idrvc=0;
    std::wstring ta;
    std::wstring tb;


    // dbStart = std::chrono::high_resolution_clock::now();
    // dbElapsed = dbEnd - dbStart;
    // wprintf(L"DB time: %0.4fs\r\n\r\n", dbElapsed.count());

#pragma region MatchDrivers
    wprintf(L"Looking for drivers...\n");
    bool doPerf=0;
    tPerf dmPerf(L"perfDevMatch");
    tPerf dnmPerf(L"perfDpDevs");
    tPerf daPerf(L"perfDrvArch");
    tPerf dddPerf(L"perfDrvHasDev");
    tPerf dcPerf(L"perfDrvClass");
    tPerf ddPerf(L"perfDrvDevs");
    tPerf dtPerf(L"perfDrvDate");
    tPerf dadPerf(L"perfDrvAdd");
    tPerf mehPerf(L"perfDevsDrvScan");
    mehPerf.start();
    for(auto&& y:devMatches){
        if(doPerf) dmPerf.start();
        if(doPerf) dnmPerf.start();
        devInfo sysDev=sysDevs[y.iDevs[0]];
        hasDev=0;
        iDev=0;
        // tb = y.devId;
        for(uint32_t x=0; x<db.dbDevices.size(); ++x){
            if(y.devId!=db.dbDevices[x]) continue;
            hasDev=1;
            iDev=x;
            break;
        }
        if(doPerf) dnmPerf.chkpt();
        if(!hasDev) continue;
        for(uint32_t x=0; x<db.dbDrivers.size(); ++x){
            if(doPerf) ddPerf.start();
            ddb::driver dpDriver=db.dbDrivers[x];

            // Skip if not correct class.
            if(sysDev.devClassGuid.size()){
                if(doPerf) dcPerf.start();
                if(sysDev.devClassGuid!=dpDriver.drvClassGuid){
                    if(doPerf) dcPerf.chkpt();
                    continue;
                }
                if(doPerf) dcPerf.chkpt();
            }

            //// Skip driver if it does not have our hwid.
            //if(doPerf) dddPerf.start();
            //hasDev=0;
            //for(uint32_t w=0; w<dpDriver.devs.size(); ++w){
            //    if(iDev!=dpDriver.devs[w].hwid) continue;
            //    hasDev=1;
            //    break;
            //}
            //if(doPerf) dddPerf.chkpt();
            //if(!hasDev) continue;

            // Skips driver if not correct Architecture.
            if(doPerf) daPerf.start();
            if(dpDriver.drvPlats.size()){
                USHORT processArch=IMAGE_FILE_MACHINE_UNKNOWN;
                USHORT nativeArch=IMAGE_FILE_MACHINE_UNKNOWN;
                std::wstring envArch=WinGetEnv(L"PROCESSOR_ARCHITECTURE");
                std::wstring curArch{L"nt"};
                curArch.reserve(envArch.size()+2);
                std::transform(envArch.begin(),envArch.end(),envArch.begin(),
                               [](wchar_t c){ return static_cast<wchar_t>(std::towlower(c)); });
                curArch+=envArch;
                if(IsWow64Process2(GetCurrentProcess(),&processArch,&nativeArch)){
                    switch(nativeArch){
                    case IMAGE_FILE_MACHINE_UNKNOWN:
                      curArch=L"Unknown";
                      break;
                    case IMAGE_FILE_MACHINE_I386:
                      curArch=L"ntx86";
                      break;
                    case IMAGE_FILE_MACHINE_AMD64:
                      curArch=L"ntamd64";
                      break;
                    case IMAGE_FILE_MACHINE_ARM:
                      curArch=L"ntarm";
                      break;
                    case IMAGE_FILE_MACHINE_ARMNT:
                      curArch=L"ntarmthumb"; // Often just "ARM"
                      break;
                    case IMAGE_FILE_MACHINE_ARM64:
                      curArch=L"ntarm64";
                      break;
                    default:
                      curArch;
                      break;

                    }
                }
                hasArch=0;
                for(std::wstring v:dpDriver.drvPlats){
                    if(v.find(curArch)==std::string::npos) continue;
                    hasArch=1;
                    break;
                }
                if(doPerf) daPerf.chkpt();
                if(!hasArch){
                    continue;
                }
            }

            // Skip if driver is older, date wise.
            if(doPerf) dtPerf.start();
            //dateNew=1;
            //if(dpDriver.drvDate.size()&&sysDev.drvLocal.drvDate.size()){
                //if(dpDriver.drvDate!=L"01-01-1970"){
                //    if(!compareDates(sysDev.drvLocal.drvDate,dpDriver.drvDate))
                //        dateNew=0;
                //}
            //}
            if(doPerf) dtPerf.chkpt();
            //if(!dateNew){
            //    continue;
            //}
            // verNew = 1;
            // if (sysDev.drvLocal.drvVer != L"" &&
            // versionCompare(sysDev.drvLocal.drvVer, dpDriver.drvVer) >= 0)
            //     verNew = 0; // Skip if the DP driver is older.
            if(doPerf) dadPerf.start();
            //if(y.driver.drvDate.size()){
            //    if(!compareDates(y.driver.drvDate,dpDriver.drvDate)) continue;
            //}
            devInfo::driver drv;
            drv.drvClass=dpDriver.drvClass;
            drv.drvClassGuid=dpDriver.drvClassGuid;
            drv.drvDate=dpDriver.drvDate;
            drv.drvPlats=dpDriver.drvPlats;
            drv.drvVer=dpDriver.drvVer;
            drv.fName=dpDriver.fName;
            drv.fPath=dpDriver.fPath;
            y.drivers.push_back(drv);

            if(doPerf) dadPerf.chkpt();
            if(doPerf) ddPerf.chkpt();
            continue;
        }
        if(doPerf) dmPerf.chkpt();
        continue;
    }
    mehPerf.chkpt(1);
    if(doPerf){
        dmPerf.stat();
        dnmPerf.stat();
        daPerf.stat();
        dcPerf.stat();
        ddPerf.stat();
        dtPerf.stat();
        dadPerf.stat();
    }

    for(auto&& y:devMatches){
        for(auto&& x:y.drivers){
            if(x.fPath.size()){
                idrvc++;
            }
        }
    }
    wprintf(L"Done (Matched: %d %s)\r\n",idrvc,
            idrvc!=1?L"drivers":L"driver");
#pragma endregion MatchDrivers

    std::wstring fPathFull;
    bool dpm;
    for(auto&& z:devMatches){
        for(auto&& x:z.drivers){
            if(!x.fPath.size()) continue;
            if(!x.fName.size()) continue;
            dpm=1;
            fPathFull=x.fPath+L"\\"+x.fName;
            for(auto&& y:matchList){
                if(fPathFull!=y) continue;
                dpm=0;
                break;
            }
            if(!dpm) continue;
            matchList.push_back(fPathFull);
        }
    }
    return true;
}

bool dpmGetSysDevs(std::vector<devInfo> &sysDevs){
    //  Get System Devices
    HDEVINFO hDevInfo;
    SP_DEVINFO_DATA DeviceInfoData;
    DWORD i;
    hDevInfo=SetupDiGetClassDevsW(NULL,0,0,DIGCF_PRESENT|DIGCF_ALLCLASSES); if(hDevInfo==INVALID_HANDLE_VALUE){
        return 1;
    }
    DeviceInfoData.cbSize=sizeof(SP_DEVINFO_DATA);
    HKEY key;
    DWORD dwcbData;
    DWORD dwType=0;
    DWORD requiredSize=0;
    size_t strSize;
    wchar_t* requestedData;
    std::wstring devinfstr;
    std::wstring devdrvregpath;
    DWORD regType;
    DWORD regSize=0;
    std::wstring drvregprefix=L"System\\CurrentControlSet\\Control\\Class\\";
    uint32_t idrvc=0;
    wprintf(L"Scanning devices...");
    for(i=0; SetupDiEnumDeviceInfo(hDevInfo,i,&DeviceInfoData); i++){
        devInfo devNfo;
        dwType=0;
        requiredSize=0;
        LONG result=SetupDiGetDeviceRegistryPropertyW(hDevInfo,
                                                      &DeviceInfoData,
                                                      SPDRP_DEVICEDESC,
                                                      &dwType,NULL,NULL,
                                                      &requiredSize);
        if(result!=ERROR_INVALID_DATA&&
           (dwType==REG_MULTI_SZ||dwType==REG_SZ)&&requiredSize>0){
            strSize=requiredSize/sizeof(wchar_t)+1;
            requestedData=new wchar_t[strSize];
            result=SetupDiGetDeviceRegistryPropertyW(
                hDevInfo,&DeviceInfoData,SPDRP_DEVICEDESC,&dwType,
                reinterpret_cast<PBYTE>(requestedData),requiredSize,
                &requiredSize);
            if(result==TRUE){
                devNfo.desc=requestedData;
            }
        }
        dwType=0;
        requiredSize=0;
        result=SetupDiGetDeviceRegistryPropertyW(hDevInfo,&DeviceInfoData,
                                                 SPDRP_CLASS,&dwType,NULL,
                                                 NULL,&requiredSize);
        if(result!=ERROR_INVALID_DATA&&
           (dwType==REG_MULTI_SZ||dwType==REG_SZ)&&requiredSize>0){
            strSize=requiredSize/sizeof(wchar_t)+1;
            requestedData=new wchar_t[strSize];
            result=SetupDiGetDeviceRegistryPropertyW(
                hDevInfo,&DeviceInfoData,SPDRP_CLASS,&dwType,
                reinterpret_cast<PBYTE>(requestedData),requiredSize,
                &requiredSize);
            if(result==TRUE){
                devNfo.devClass=requestedData;
            }
        }
        dwType=0;
        requiredSize=0;
        result=SetupDiGetDeviceRegistryPropertyW(hDevInfo,&DeviceInfoData,
                                                 SPDRP_CLASSGUID,&dwType,
                                                 NULL,NULL,&requiredSize);
        if(result!=ERROR_INVALID_DATA&&
           (dwType==REG_MULTI_SZ||dwType==REG_SZ)&&requiredSize>0){
            strSize=requiredSize/sizeof(wchar_t)+1;
            requestedData=new wchar_t[strSize];
            result=SetupDiGetDeviceRegistryPropertyW(
                hDevInfo,&DeviceInfoData,SPDRP_CLASSGUID,&dwType,
                reinterpret_cast<PBYTE>(requestedData),requiredSize,
                &requiredSize);
            if(result==TRUE){
                devNfo.devClassGuid=requestedData;
            }
        }
        dwType=0;
        requiredSize=0;
        result=SetupDiGetDeviceRegistryPropertyW(hDevInfo,&DeviceInfoData,
                                                 SPDRP_HARDWAREID,&dwType,
                                                 NULL,NULL,&requiredSize);
        if(result!=ERROR_INVALID_DATA&&
           (dwType==REG_MULTI_SZ||dwType==REG_SZ)&&requiredSize>0){
            strSize=requiredSize/sizeof(wchar_t)+1;
            requestedData=new wchar_t[strSize];
            result=SetupDiGetDeviceRegistryPropertyW(
                hDevInfo,&DeviceInfoData,SPDRP_HARDWAREID,&dwType,
                reinterpret_cast<PBYTE>(requestedData),requiredSize,
                &requiredSize);
            if(result==TRUE){
                while(L'\0'!=*requestedData){
                    devinfstr=requestedData;
                    std::transform(devinfstr.begin(),devinfstr.end(),
                                   devinfstr.begin(),
                                   ::tolower);
                    devNfo.hwids.push_back(devinfstr);
                    requestedData+=1+devNfo.hwids.back().size();
                    // devinfstr.clear();
                }
            }
        }
        dwType=0;
        requiredSize=0;
        result=SetupDiGetDeviceRegistryPropertyW(hDevInfo,&DeviceInfoData,
                                                 SPDRP_COMPATIBLEIDS,&dwType,
                                                 NULL,NULL,&requiredSize);
        if(result!=ERROR_INVALID_DATA&&
           (dwType==REG_MULTI_SZ||dwType==REG_SZ)&&requiredSize>0){
            strSize=requiredSize/sizeof(wchar_t)+1;
            requestedData=new wchar_t[strSize];
            result=SetupDiGetDeviceRegistryPropertyW(
                hDevInfo,&DeviceInfoData,SPDRP_COMPATIBLEIDS,&dwType,
                reinterpret_cast<PBYTE>(requestedData),requiredSize,
                &requiredSize);
            if(result==TRUE){
                while(L'\0'!=*requestedData){
                    devinfstr=requestedData;
                    std::transform(devinfstr.begin(),devinfstr.end(),
                                   devinfstr.begin(),
                                   ::tolower);
                    devNfo.chwids.push_back(devinfstr);
                    requestedData+=1+devNfo.chwids.back().size();
                }
            }
        }
        dwType=0;
        requiredSize=0;
        result=SetupDiGetDeviceRegistryPropertyW(hDevInfo,&DeviceInfoData,
                                                 SPDRP_DRIVER,&dwType,NULL,
                                                 NULL,&requiredSize);
        if(result!=ERROR_INVALID_DATA&&
           (dwType==REG_MULTI_SZ||dwType==REG_SZ)&&requiredSize>0){
            strSize=requiredSize/sizeof(wchar_t)+1;
            requestedData=new wchar_t[strSize];
            devNfo.drvLocal.drvVer=L"0.0.0.0";
            devNfo.drvLocal.drvDate=L"1970-01-01";
            devNfo.drvLocal.fPath=L"Windows\\Inf";
            result=SetupDiGetDeviceRegistryPropertyW(
                hDevInfo,&DeviceInfoData,SPDRP_DRIVER,&dwType,
                reinterpret_cast<PBYTE>(requestedData),requiredSize,
                &requiredSize);
            if(result==TRUE){
                devdrvregpath=(drvregprefix+requestedData).c_str();
                std::transform(devdrvregpath.begin(),devdrvregpath.end(),
                               devdrvregpath.begin(),::tolower);
                // std::wprintf((devdrvregpath + L"\r\n").c_str());
                result=RegOpenKeyExW(HKEY_LOCAL_MACHINE,devdrvregpath.c_str(),0,
                                     KEY_QUERY_VALUE,&key);
                if(result==ERROR_SUCCESS){
                    regSize=0;
                    regType=0;

                    if(RegQueryValueExW(key,L"DriverVersion",nullptr,&regType,
                                        nullptr,&regSize)==ERROR_SUCCESS){
                        if(regType==REG_SZ||regType==REG_EXPAND_SZ){
                            std::wstring regData(regSize/sizeof(WCHAR),L'\0');
                            if(RegQueryValueExW(key,L"DriverVersion",nullptr,&regType,
                                                reinterpret_cast<LPBYTE>(&regData[0]),
                                                &regSize)==ERROR_SUCCESS){
                                regData.resize(wcslen(regData.c_str()));
                                devNfo.drvLocal.drvVer=regData;
                            }
                        }
                    }
                    regSize=0;
                    regType=0;
                    if(RegQueryValueExW(key,L"DriverDate",nullptr,&regType,
                                        nullptr,
                                        &regSize)==ERROR_SUCCESS){
                        if(regType==REG_SZ||regType==REG_EXPAND_SZ){
                            std::wstring regData(regSize/sizeof(WCHAR),L'\0');
                            if(RegQueryValueExW(key,L"DriverDate",nullptr,&regType,
                                                reinterpret_cast<LPBYTE>(&regData[0]),
                                                &regSize)==ERROR_SUCCESS){
                                regData.resize(wcslen(regData.c_str()));
                                devNfo.drvLocal.drvDate=regData;
                            }
                        }
                    }
                    regSize=0;
                    regType=0;
                    devNfo.drvLocal.fPath=L"";
                    if(RegQueryValueExW(key,L"InfPath",nullptr,&regType,nullptr,
                                        &regSize)==ERROR_SUCCESS){
                        if(regType==REG_SZ||regType==REG_EXPAND_SZ){
                            std::wstring regData(regSize/sizeof(WCHAR),L'\0');
                            if(RegQueryValueExW(key,L"InfPath",nullptr,&regType,
                                                reinterpret_cast<LPBYTE>(&regData[0]),
                                                &regSize)==ERROR_SUCCESS){
                                regData.resize(wcslen(regData.c_str()));
                                devNfo.drvLocal.fName=regData;
                            }
                        }
                    }
                    RegCloseKey(key);
                }
                // devNfo.hwids.push_back(devdrvregpath);
            }
        }
        if(devNfo.hwids.size()>0) idrvc++;
        sysDevs.push_back(devNfo);
    }
    //delete[] requestedData;
    SetupDiDestroyDeviceInfoList(hDevInfo);
    wprintf(L"Done (Found: %d %s)\r\n",idrvc,
            idrvc>1?L"devices":L"device");
}
bool dpmGenDDB(ddb& db, std::vector<vecBuf>& fList){
    std::vector<dpStrRef> dpStrRefs;
    uint32_t dpStrRefPos=0;
    uint32_t dpDevRefPos=0;
    std::wstring line;
    std::wstring tmpLine;
    std::wstring sect;
    std::vector<std::wstring> mfgsects;
    std::wstring submfgr;
    std::wstring submfgs;
    std::vector<vecInfSect> vecInf;
    ddb::driver newDriver;
    std::wstringstream sInf;
    std::wstring infPath;
    vecInfSect infSect;
    std::wstring tmps;
    std::wstring sectTmp;
    std::wstring tmps2;
    std::wstring strAssign;
    std::wstringstream ms;
    uint32_t preallocSect;
    uint32_t preallocSectLines;
    std::streampos preallocSectLinesSsPos;
    uint32_t preallocDevRef=0;
    uint32_t iLine=0;
    dpStrRef sref;
    std::vector<std::wstring> vInf;
    bool sCapt;
    bool noDrvVer=false;
    tPerf perfDB(L"perfDB");
    tPerf perfPP(L"perfPP");
    tPerf perfMeta(L"perfMeta");
    tPerf perfDev(L"perfDev");
    tPerf perfInf(L"perfInf");
    perfDB.start();
    for(uint32_t j=0; j<fList.size(); ++j){
        if(fList[j].fData.size()==0){
            continue;
        }
        perfInf.start();
        wprintf(L"%u\\%zu (%0.2f%%): %s\r\n",j+1,fList.size(),(static_cast<double>(j+(uint32_t)1)/static_cast<double>(fList.size()))*100,fList[j].fPath.c_str());
        newDriver.reset();
        if(std::regex_match(fList[j].fPath,exp_fnp)){
            newDriver.fPath=std::regex_replace(fList[j].fPath,exp_fnp,L"$1");
            newDriver.fName=std::regex_replace(fList[j].fPath,exp_fnp,L"$2");
        } else{
            newDriver.fPath=L".";
            newDriver.fName=fList[j].fPath;
        }
        // continue;
        sInf.clear();
        sInf.str(L"");
        sInf.str(fList[j].fData.c_str()+'\0\0');
        perfPP.start();
        mfgsects.clear();
        // PreAlloc Sections
        sInf.clear();
        sInf.seekg(0,std::ios::beg);
        vecInf.clear();
        vecInf.shrink_to_fit();
        infSect.sect.clear();
        infSect.lines.clear();
        preallocSect=0;
        noDrvVer=true;
        /*std::split(vInf,fList[j].fData,)*/
        /*split_regex;*/
        // std::algorithm::split_regex(vInf,fList[j].fData,regex("___"));
        // continue;
        while(!getline(sInf,line).eof()){
            preallocSect++;
        }
        vecInf.reserve(preallocSect);
        // Process Sections
        preallocSectLines=0;
        sInf.clear();
        sInf.seekg(0,std::ios::beg);
        preallocSectLinesSsPos=sInf.tellg();
        iLine=0;
        while(getline(sInf,line)){
            iLine++;
            if(lineFilter(line))
                continue;
            if(std::regex_match(line,exp_s)){
                std::transform(line.begin(),line.end(),line.begin(),::tolower);
                if(!infSect.sect.empty()&&infSect.lines.size()>0){
                    sectTmp=infSect.sect;
                    if(infSect.sect==L"version"||infSect.sect==L"manufacturer"||
                       infSect.sect==L"strings"){
                        infSect.lines.shrink_to_fit();
                        vecInf.push_back(infSect);
                    } else{
                        if(std::find(mfgsects.begin(),mfgsects.end(),infSect.sect)!=
                           mfgsects.end()){
                            infSect.lines.shrink_to_fit();
                            // if(mfgsects.size()>2&&j>=28){
                            //     wcout<<L"catch";
                            // }
                            vecInf.push_back(infSect);
                        }
                    }
                    // preallocSectLines=0;
                    infSect.lines.clear();
                    // infSect.lines.shrink_to_fit();
                    infSect.sect.clear();
                    // vector<wstring>().swap(infSect.lines);
                    // wstring().swap(infSect.sect);
                }
                infSect.sect=std::regex_replace(line,exp_s,L"$1");
                infSect.lines.reserve(preallocSect);
                //if((infSect.sect!=L"version"&&infSect.sect!=L"manufacturer"&&infSect.sect!=L"strings")&&!(std::find(mfgsects.begin(),mfgsects.end(),infSect.sect)!=mfgsects.end())){
                //    infSect.sect.clear();
                //}
                continue;
            }

            if(!infSect.sect.empty()){
                if(infSect.sect!=L"strings"){
                    // std::transform(line.begin(),line.end(),line.begin(),::tolower);
                    std::transform(line.begin(),line.end(),line.begin(),::tolower);
                }
                trim(line);
                if(lineFilter(line))
                    continue;
                infSect.lines.push_back(move(std::regex_replace(line,ea,L"$1")));
                if(infSect.sect==L"manufacturer"){
                    // std::algorithm::trim(line);
                    // if(lineFilter(line)) continue;
                    if(std::regex_match(line,exp_mfgm)){
                        submfgr=std::regex_replace(line,exp_mfgm,L"$1");
                        trim(submfgr);
                        mfgsects.push_back(submfgr);
                        submfgs.clear();
                        ms.str(std::regex_replace(line,exp_mfgm,L"$2"));
                        ms.clear();
                        while(std::getline(ms,submfgs,L',')){
                            trim(submfgs);
                            std::wstring smfgs=submfgr+L'.'+submfgs;
                            mfgsects.push_back(smfgs);
                            if(std::find(newDriver.drvPlats.begin(),
                                         newDriver.drvPlats.end(),
                                         submfgs)==newDriver.drvPlats.end()){
                                newDriver.drvPlats.push_back(submfgs);
                            }
                        }
                    } else{
                        std::wprintf(L"~!MfgMisMatch@%s\\%s:%u= %s\r\n", newDriver.fPath.c_str(), newDriver.fName.c_str(), iLine, line.c_str());
                    }
                }
            }
        }
        // if(newDriver.fName==L"bossa.inf"){
        //     wcout<<L"catch";
        // }
        if(!infSect.sect.empty()&&infSect.lines.size()>0){
            // std::algorithm::trim(line);
            //
            if(!line.empty()&&line.at(0)!=L'\r'&&line.at(0)!=L';'&&line.size()>1){
                // if(std::regex_match(line,ea)){
                // infSect.lines.push_back(std::regex_replace(line,ea,L"$1"));
                if(!lineFilter(line)) infSect.lines.push_back(line);
                //} else{
                //
                std::wprintf(L"~!AssignMisMatch@%s\\%s:%u= %s\r\n", newDriver.fPath.c_str(), newDriver.fName.c_str(), iLine, line.c_str());
                //    wcout<<endl;
                //    continue;
                //}
                //}
                infSect.lines.shrink_to_fit();
                vecInf.push_back(infSect);
                preallocSectLines=0;
                infSect.lines.clear();
                infSect.lines.shrink_to_fit();
                infSect.sect.clear();
            } else {
              if (iLine >= preallocSect) {
                if (infSect.sect == L"version" || infSect.sect == L"manufacturer" ||
                  infSect.sect == L"strings") {
                  infSect.lines.shrink_to_fit();
                  vecInf.push_back(infSect);
                }
                else {
                  if (std::find(mfgsects.begin(), mfgsects.end(), infSect.sect) !=
                    mfgsects.end()) {
                    infSect.lines.shrink_to_fit();
                    // if(mfgsects.size()>2&&j>=28){
                    //     wcout<<L"catch";
                    // }
                    vecInf.push_back(infSect);
                  }
                }
                preallocSectLines = 0;
                infSect.lines.clear();
                infSect.lines.shrink_to_fit();
                infSect.sect.clear();
              }
            }
            if(vecInf.size()==0){
                // Inf contains no sections.
                continue;
            }
            if(!vecInfHasSect(vecInf,L"version")){
                wprintf(L"~!noVerSect\r\n");
                continue;
            }
            if(!vecInfHasSect(vecInf,L"strings")){
                wprintf(L"~!noStrSect\r\n");
                //continue;
            }
            if(!vecInfHasSect(vecInf,L"manufacturer")){
                wprintf(L"~!noMfgSect\r\n");
                continue;
            }
            // sInf.str(std::wstring());
            // extractCallbackSpec->vecBufReset(vInf);
            // extractCallbackSpec->vecBufReset(vInfs[j]);
            // vector<wstring>().swap(mfgsects);
            perfPP.chkpt();
            // wprintf(L"PreProc time: %0.4fs\r\n", ppElapsed.count());
            // if(ppElapsed.count()>=4){
            //     wcout<<"catch";
            // }
            line.clear();
            sInf.str(std::wstring());
            sInf.clear();
            // continue;
            perfMeta.start();
            // preallocStrRef=0;
            dpStrRefs.clear();

            for(auto&& x:vecInf){
                sect.clear();
                sect=x.sect;
                // std::transform(sect.begin(),sect.end(),sect.begin(),::tolower);
                if(x.sect==L"version"){
                    for(auto&& y:x.lines){
                        //
                        // if (newDriver.fName == L"hellofacemigration.inf")
                        //    assert("test");
                        if(std::regex_match(y,exp_dvsm)){
                            noDrvVer=false;
                            if(std::regex_match(y,exp_dv)){
                                std::wstring ddate=std::regex_replace(y,exp_dv,L"$1");
                                std::wstring dver=std::regex_replace(y,exp_dv,L"$2");
                                if(ddate.size()!=y.size()){
                                    newDriver.drvDate=ddate;
                                }
                                if(dver.size()!=y.size()){
                                    newDriver.drvVer=dver;
                                }

                                /*} else if(std::regex_match(y,exp_dvod)){
                                    wstring ddate=std::regex_replace(y, exp_dvod,L"$1");
                                    if (ddate.size() != y.size()) {
                                        newDriver.drvDate=ddate;
                                    }*/
                            } else{
                                wprintf(L"~!VerMisMatch@%s\\%s,%s\r\n",newDriver.fPath.c_str(),
                                        newDriver.fName.c_str(),y.c_str());
                            }
                        }
                        if(std::regex_match(y,exp_dc)){
                            std::wstring dclass=std::regex_replace(y,exp_dc,L"$1");
                            newDriver.drvClass=dclass;
                        }
                        if(std::regex_match(y,exp_dg)){
                            std::wstring dguid=std::regex_replace(y,exp_dg,L"$1");
                            newDriver.drvClassGuid=dguid;
                        }
                    }
                } else if(x.sect==L"strings"){
                    // for(auto&& y:x.lines){
                    //     preallocStrRef++;
                    // }
                    // dpStrRefs.reserve(preallocStrRef);
                    sCapt=false;
                    for(auto&& y:x.lines){
                        if(std::regex_match(y,exp_saqm)){
                            sref.sRef=std::regex_replace(y,exp_sra,L"$1");
                            sref.sDef=std::regex_replace(y,exp_sra,L"$2");
                            sCapt=true;
                        } else if(std::regex_match(y,exp_sam)){
                            sref.sRef=std::regex_replace(y,exp_sam,L"$1");
                            sref.sDef=std::regex_replace(y,exp_sam,L"$2");
                            sCapt=true;
                        } else if(std::regex_match(y,exp_sabm)){
                            sref.sRef=std::regex_replace(y,exp_sabm,L"$1");
                            sref.sDef=std::regex_replace(y,exp_sabm,L"$2");
                            sCapt=true;
                        } else{
                            wprintf(L"~!InvStrAssign@%s\\%s,%s\r\n",newDriver.fPath.c_str(),
                                    newDriver.fName.c_str(),y.c_str());
                        }
                        if(sCapt){
                            trim(sref.sRef);
                            trim(sref.sDef);
                            std::transform(sref.sRef.begin(),sref.sRef.end(),
                                           sref.sRef.begin(),::tolower);
                            bool hasStr=false;
                            for(auto&& y:dpStrRefs){
                                if(y.sRef==sref.sRef){
                                    if(y.sDef!=sref.sDef){
                                        wprintf(L"~!RefAltDef@%s\\%s,\"%s\"==\"%s\"!=\"%s\"\r\n",
                                                newDriver.fPath.c_str(),newDriver.fName.c_str(),
                                                y.sRef.c_str(),y.sDef.c_str(),sref.sDef.c_str());
                                    }
                                    hasStr=true;
                                    break;
                                }
                            }
                            if(!hasStr) dpStrRefs.push_back(sref);
                        }
                    }
                    // for(auto&& y:dpStrRefs){
                    //     trim(y.sRef);
                    //     trim(y.sDef);
                    //
                    //std::transform(y.sRef.begin(),y.sRef.end(),y.sRef.begin(),::tolower);
                    // }
                    dpStrRefs.shrink_to_fit();
                }
            }
            perfMeta.chkpt();
            // wprintf(L"MetaProc time: %0.4fs\r\n", metaElapsed.count());
            // std::cout<<"MetaProc time: "<<metaElapsed.count()<<"s\n";
            perfDev.start();
            for(auto&& x:mfgsects){
                for(auto&& y:vecInf){
                    if(y.sect!=x){
                        continue;
                    }
                    preallocDevRef+=(uint32_t)y.lines.size();
                    // for(auto&& z:y.lines){
                    //     preallocDevRef++;
                    // }
                }
            }
            newDriver.devs.reserve(preallocDevRef);
            for(auto&& x:mfgsects){
                for(auto&& y:vecInf){
                    if(y.sect!=x){
                        continue;
                    }
                    for(auto&& z:y.lines){
                        if(std::regex_match(z,exp_mfgd)){
                            bool isNew=true;
                            bool invStr=true;
                            uint32_t iDev=0;
                            std::wstring devHwid=std::regex_replace(z,exp_mfgd,L"$2");
                            // for(auto&& v:newDB.dbDevices){
                            //     for(auto&& x:newDriver.devs){
                            //         iDev++;
                            //         if(devHwid==v&&x.hwid==iDev){
                            //             isNew=false;
                            //             break;
                            //         }
                            //     }
                            //     if(!isNew){
                            //         break;
                            //     }
                            // }
                            if(isNew){
                                ddb::driver::dev newDev;
                                std::wstring desc=std::regex_replace(z,exp_mfgd,L"$1");
                                std::wstring strTmp=desc;
                                if(std::regex_match(desc,exp_inlsrm)){
                                    // strTmp=std::regex_replace(desc,exp_inlsr,L"$1");
                                    //
                                    std::transform(desc.begin(),desc.end(),desc.begin(),::tolower);
                                    std::transform(desc.begin(),desc.end(),desc.begin(),
                                                   ::tolower);
                                    std::transform(devHwid.begin(),devHwid.end(),
                                                   devHwid.begin(),
                                                   ::tolower);
                                    strTmp=std::regex_replace(desc,exp_inlsrm,L"$1");
                                    strTmp=std::regex_replace(strTmp,exp_sr,L"$1");
                                    for(auto&& w:dpStrRefs){
                                        if(w.sRef==strTmp){
                                            strTmp=w.sDef;
                                            invStr=false;
                                            break;
                                        }
                                    }
                                    desc=std::regex_replace(desc,exp_inlsr,strTmp);
                                    trim(desc);
                                    if(std::regex_match(desc,exp_srq)){
                                        desc=std::regex_replace(strTmp,exp_srq,L"$1");
                                        invStr=false;
                                    }
                                    if(invStr){
                                        wprintf(L"~!StrRefNoMatch@%s\\%s,%s\r\n",
                                                newDriver.fPath.c_str(),newDriver.fName.c_str(),
                                                z.c_str());
                                    }
                                    bool isNewStr=true;
                                    bool isNewDev=true;
                                    uint32_t iStr=0;
                                    iDev=0;
                                    for(uint32_t idx=0; (uint32_t)idx<db.dbDevices.size(); ++idx){
                                        if(devHwid==db.dbDevices[idx]){
                                            iDev=idx;
                                            isNewDev=false;
                                            break;
                                        }
                                    }
                                    // for(auto&& v:dp.dbDevices){
                                    //     iDev++;
                                    //     if(devHwid==v){
                                    //         isNewDev=false;
                                    //         break;
                                    //     }
                                    // }
                                    for(uint32_t idx=0; idx<(uint32_t)db.dbStrings.size(); ++idx){
                                        if(desc==db.dbStrings[idx]){
                                            iStr=idx;
                                            isNewStr=false;
                                            break;
                                        }
                                    }
                                    // for(auto&& v:dp.dbStrings){
                                    //     iStr++;
                                    //     if(desc==v){
                                    //         isNewStr=false;
                                    //         break;
                                    //     }
                                    // }
                                    if(isNewStr){
                                        trim(desc);
                                        db.dbStrings.push_back(desc);
                                        newDev.desc=dpStrRefPos;
                                        dpStrRefPos++;
                                    } else{
                                        newDev.desc=iStr;
                                    }
                                    if(isNewDev){
                                        trim(devHwid);
                                        db.dbDevices.push_back(devHwid);
                                        newDev.hwid=dpDevRefPos;
                                        dpDevRefPos++;
                                    } else{
                                        newDev.hwid=iDev;
                                    }
                                    newDriver.devs.push_back(newDev);
                                } else{
                                    wprintf(L"~!StrAssignMisMatch@%s\\%s,%s\r\n",
                                            newDriver.fPath.c_str(),newDriver.fName.c_str(),
                                            z.c_str());
                                }
                            }
                        } else{
                            wprintf(L"~!DevMisMatch@%s\\%s,%s\r\n",newDriver.fPath.c_str(),
                                    newDriver.fName.c_str(),z.c_str());
                        }
                    }
                }
            }
            newDriver.devs.shrink_to_fit();
            perfDev.chkpt();
            // wprintf(L"DevProc time: %0.4fs\r\n", devElapsed.count());
            if(newDriver.drvVer.empty()&&newDriver.drvDate.empty()){
                if(vecInfSectHasVal(vecInf,L"version",exp_dvsm)){
                    wprintf(L"~!NoVerDef@%s\\%s\r\n",newDriver.fPath.c_str(),
                            newDriver.fName.c_str());
                }
            }
            /*if (newDriver.fName==L"FOH02.inf"){
                continue;
            }*/
            if(newDriver.devs.size()==0){
                wprintf(L"~!NoDevs@%s\\%s\r\n",newDriver.fPath.c_str(),
                        newDriver.fName.c_str());
            }
            if(newDriver.devs.size()){
                if(newDriver.drvDate.size()==0&&newDriver.drvVer.size()==0){
                    if(noDrvVer){
                        wprintf(L"~!NoVerInfo@%s\\%s\r\n",newDriver.fPath.c_str(),
                                newDriver.fName.c_str());
                    } else{
                        wprintf(L"~!VerMisMatch@%s\\%s\r\n",newDriver.fPath.c_str(),
                                newDriver.fName.c_str());
                    }
                }
                if(newDriver.drvDate.size()==0) newDriver.drvDate=L"01-01-1970";
                if(newDriver.drvVer.size()==0) newDriver.drvVer=L"0.0.0.0";
                db.dbDrivers.push_back(newDriver);
            }
            newDriver.devs.clear();
            newDriver.drvDate.clear();
            newDriver.drvPlats.clear();
            newDriver.drvVer.clear();
            newDriver.fName.clear();
            newDriver.fPath.clear();
            newDriver.devs.shrink_to_fit();
            newDriver.drvDate.shrink_to_fit();
            newDriver.drvPlats.shrink_to_fit();
            newDriver.drvVer.shrink_to_fit();
            newDriver.fName.shrink_to_fit();
            newDriver.fPath.shrink_to_fit();
            mfgsects.clear();
            mfgsects.shrink_to_fit();
            vecInf.clear();
            vecInf.shrink_to_fit();
            perfInf.chkpt();
            fList[j].fData.clear();
            fList[j].fData.shrink_to_fit();
            // wprintf(L"Inf time: %0.4fs\r\n\r\n", infElapsed.count());
            // std::cout<<"Inf time: "<<infElapsed.count()<<"s\n\n";
        }
    }
    dpStrRefs.clear();
    dpStrRefs.shrink_to_fit();
    dpStrRefPos=0;
    dpDevRefPos=0;
    db.dbStrings.shrink_to_fit();
    db.dbDevices.shrink_to_fit();
    db.dbDrivers.shrink_to_fit();
    fList.clear();
    fList.shrink_to_fit();
    perfDB.chkpt();
    perfPP.stat();
    perfMeta.stat();
    perfDev.stat();
    perfInf.stat();
    perfDB.stat();
    return true;

}
bool dpmReadDDB(ddb& db, std::wstring ddbPath){
    std::ifstream ifs(ddbPath,std::ios::binary|std::ios::ate);
    if(!ifs.is_open()){
        return false;
    }
    std::ifstream::pos_type pos=ifs.tellg();
    std::vector<char> buf(pos);
    ifs.seekg(0,std::ios::beg);
    ifs.read(&buf[0],pos);
    ifs.close();
    //uint16_t l=9;
    uint32_t p=0;
    uint32_t vl=0;
    uint32_t svl=0;
    std::vector<char> vStr;
    std::vector<wchar_t> vwStr;
    std::wstring twStr;
    dbGetUINT(buf,p,vStr,vl);
    dbRawRead(buf,vl+1,p,vStr);
    db.dbMagic=s2ws(std::string(vStr.begin(),vStr.end()));
    dbGetUINT(buf,p,vStr,db.dbSpec);
    dbGetUINT(buf,p,vStr,vl);
    db.dbStrings.reserve(vl);
    while(db.dbStrings.size()<vl){
        twStr.clear();
        dbGetWStr(buf,p,vStr,twStr);
        db.dbStrings.push_back(twStr);
    }
    dbGetUINT(buf,p,vStr,vl);
    db.dbDevices.reserve(vl);
    while(db.dbDevices.size()<vl){
        twStr.clear();
        dbGetWStr(buf,p,vStr,twStr);
        db.dbDevices.push_back(twStr);
    }
    dbGetUINT(buf,p,vStr,vl);
    db.dbDrivers.reserve(vl);
    while(db.dbDrivers.size()<vl){
        ddb::driver drvr;
        dbGetWStr(buf,p,vStr,drvr.fPath);
        dbGetWStr(buf,p,vStr,drvr.fName);
        dbGetWStr(buf,p,vStr,drvr.drvDate);
        dbGetWStr(buf,p,vStr,drvr.drvVer);
        dbGetWStr(buf,p,vStr,drvr.drvClass);
        dbGetWStr(buf,p,vStr,drvr.drvClassGuid);
        dbGetUINT(buf,p,vStr,svl);
        drvr.drvPlats.reserve(svl);
        while(drvr.drvPlats.size()<svl){
            twStr.clear();
            dbGetWStr(buf,p,vStr,twStr);
            drvr.drvPlats.push_back(twStr);
        }
        dbGetUINT(buf,p,vStr,svl);
        drvr.devs.reserve(svl);
        while(drvr.devs.size()<svl){
            ddb::driver::dev drvd;
            dbGetUINT(buf,p,vStr,drvd.desc);
            dbGetUINT(buf,p,vStr,drvd.hwid);
            drvr.devs.push_back(drvd);
        }
        db.dbDrivers.push_back(drvr);
    }

    buf.clear();
    buf.shrink_to_fit();
    return true;
}
bool dpmWriteDDB(ddb& db,std::wstring ddpPath){
    std::ofstream outFile(ddpPath.c_str(),std::ios::out|std::ios::binary);
    uint16_t l=(uint16_t)ws2s(db.dbMagic).length();
    wFDB(outFile,db.dbMagic.size());
    outFile.write((char*)ws2s(db.dbMagic).data(),(l+1)*sizeof(char));
    wFDB(outFile,db.dbSpec);
    wFDB(outFile,db.dbStrings.size());
    for(size_t vi=0; vi<db.dbStrings.size(); ++vi){
        wFDB(outFile,db.dbStrings[vi]);
    }
    wFDB(outFile,db.dbDevices.size());
    for(size_t vi=0; vi<db.dbDevices.size(); ++vi){
        wFDB(outFile,db.dbDevices[vi]);
    }
    wFDB(outFile,db.dbDrivers.size());
    for(ddb::driver d:db.dbDrivers){
        wFDB(outFile,d.fPath);
        wFDB(outFile,d.fName);
        wFDB(outFile,d.drvDate);
        wFDB(outFile,d.drvVer);
        wFDB(outFile,d.drvClass);
        wFDB(outFile,d.drvClassGuid);
        wFDB(outFile,d.drvPlats.size());
        for(std::wstring s:d.drvPlats){
            wFDB(outFile,s);
        }
        wFDB(outFile,d.devs.size());
        for(ddb::driver::dev dv:d.devs){
            wFDB(outFile,dv.desc);
            wFDB(outFile,dv.hwid);
        }
    }
    outFile.close();
    return true;
}


//HRESULT ExtractTxtFiles(
//    IInArchive* archive,                   // 7z archive interface
//    std::vector<std::pair<UString,std::string>>& txtFiles  // Output: vector of (name, content)
//){
//    UInt32 numItems=0;
//    HRESULT result=archive->GetNumberOfItems(&numItems);
//    if(result!=S_OK) return result;
//
//    for(UInt32 i=0; i<numItems; ++i){
//        NWindows::NCOM::CPropVariant fileNameProp;
//        result=archive->GetProperty(i,kpidPath,&fileNameProp);
//        if(result!=S_OK) return result;
//
//        if(fileNameProp.vt==VT_BSTR){
//            UString fileName=fileNameProp.bstrVal;
//            // Check if the file ends with ".txt"
//            if(fileName.Right(4).CompareNoCase(L".txt")==0){
//                // Extract the file contents into a buffer
//                CMyComPtr<ISequentialOutStream> outStream=new COutMemStream();
//                Int32 extractionResult=0;
//                result=archive->Extract(&i,1,0,outStream,& extractionResult);
//                if(result!=S_OK||extractionResult!=NArchive::NExtract::NOperationResult::kOK){
//                    return E_FAIL;
//                }
//
//                // Retrieve the contents from the memory stream
//                COutMemStream* memStream=static_cast<COutMemStream*>(outStream.GetInterface());
//                std::string fileContent(memStream->GetBuffer(),memStream->GetSize());
//
//                // Store the file name and content as a pair
//                txtFiles.push_back(std::make_pair(fileName,fileContent));
//            }
//        }
//    }
//    return S_OK;
//}


bool dpGetInfs(dp& oDP){

    //CByteBuffer _outMemBuf;
    //CBufPtrSeqOutStream* _bufPtrSeqOutStream_Spec;
    //CMyComPtr<ISequentialOutStream> _bufPtrSeqOutStream;
    //CMyComPtr2_Create<ISequentialOutStream,CBufPtrSeqOutStream> outStream;

//    HRESULT Update(
//        DECL_EXTERNAL_CODECS_LOC_VARS
//        const CObjectVector<CItemEx> &inputItems,
//        CObjectVector<CUpdateItem> &updateItems,
//        ISequentialOutStream*seqOutStream,
//        CInArchive*inArchive,bool removeSfx,
//        const CUpdateOptions&updateOptions,
//        const CCompressionMethodMode&compressionMethodMode,
//        IArchiveUpdateCallback*updateCallback);
//
//}}

    //CArchiveExtractCallback* extractCallbackSpec=new CArchiveExtractCallback;
    //CMyComPtr<IArchiveExtractCallback> extractCallback(extractCallbackSpec);

    //                CExtractCallbackConsole                 *ecs            = new CExtractCallbackConsole;
    //                CMyComPtr<IFolderArchiveExtractCallback> extractCallback= ecs;

    //Func_CreateObject createObjectFunc=(Func_CreateObject)lib.GetProc("CreateObject");
    //if(!createObjectFunc){
    //    PrintError("Can not get CreateObject");
    //    return false;
    //}
    //CMyComPtr<IInArchive> archive;
    //if(createObjectFunc(&CLSID_Format,&IID_IInArchive,(void**)&archive)!=S_OK){
    //    PrintError("Can not get class object");
    //    return false;
    //}
    //FString archiveName=CmdStringToFString(ws2s(wstring(dpsPath)+L"\\"+oDP.dpFileName).c_str());
    //CInFileStream* fileSpec=new CInFileStream;
    //CMyComPtr<IInStream> file=fileSpec;
    //if(!fileSpec->Open(archiveName)){
    //    PrintError("Can not open archive file",archiveName);
    //    return false;
    //}
    //CArchiveOpenCallback* openCallbackSpec=new CArchiveOpenCallback;
    //CMyComPtr<IArchiveOpenCallback> openCallback(openCallbackSpec);
    //openCallbackSpec->PasswordIsDefined=false;
    //const UInt64 scanSize=1<<23;
    //if(archive->Open(file,&scanSize,openCallback)!=S_OK){
    //    PrintError("Can not open file as archive",archiveName);
    //    return false;
    //}
    //CArchiveExtractCallbackMem* extractCallbackSpec=new CArchiveExtractCallbackMem;
    //CMyComPtr<CArchiveExtractCallbackMem> extractCallback(extractCallbackSpec);
    //extractCallbackSpec->Init(archive,L"^.*\\.inf$"); // second parameter is output folder path
    //extractCallbackSpec->PasswordIsDefined=false;
    //HRESULT result=archive->Extract(NULL,(UInt32)(Int32)(-1),false,extractCallback);
    //if(result!=S_OK){
    //    PrintError("Extract Error");
    //    return false;
    //}
    ////return extractCallbackSpec->_vBuf;
    //oDP.vInfs=extractCallbackSpec->_vBuf;
    //extractCallbackSpec->_vBuf.clear();
    //extractCallbackSpec->_vBuf.shrink_to_fit();
    return true;
}

//
// int dpmMain() {
//   std::string ret;
//   bool bUpdate = 1;  // true;
//   std::locale loc;



//   return 0;
// }

// #include "../../Common/MyWindows.h"
// #include "../../Common/Defs.h"
// #include "../../Common/MyInitGuid.h"
// #include "../../Common/IntToString.h"
// #include "../../Common/StringConvert.h"
// #include "../../Windows/DLL.h"
// #include "../../Windows/FileDir.h"
// #include "../../Windows/FileFind.h"
// #include "../../Windows/FileName.h"
// #include "../../Windows/NtCheck.h"
// #include "../../Windows/PropVariant.h"
// #include "../../Windows/PropVariantConv.h"
//
// #include "FileStreams.h"
// #include "StreamObjects.h"
//
// #include "../Archive/IArchive.h"
//
// #include "../IPassword.h"
// #include "../../../C/7zVersion.h"
//
// using namespace NWindows;
// using namespace NFile;
// using namespace NDir;
//

//
// DEFINE_GUID(CLSID_Format, 0x23170F69, 0x40C1, 0x278A, 0x10, 0x00, 0x00, 0x01,
//            0x10, 0x07, 0x00, 0x00);
// NDLL::CLibrary lib;
//

//
// void vecBufReset(vecBuf& vec) {
//  // std::wstring().swap(vec.fData);
//  vec.fData.clear();
//  vec.fData.shrink_to_fit();
//  vec.fIndex = 0;
//  vec.fPath = std::wstring();
//}
//
//
////STDMETHODIMP CArchiveExtractCallbackMem::SetOperationResult(
////    Int32 operationResult) {
////  switch (operationResult) {
////    case NArchive::NExtract::NOperationResult::kOK:
////      break;
////    default: {
////      NumErrors++;
////      Print("  :  ");
////      const char* s = NULL;
////      switch (operationResult) {
////        case NArchive::NExtract::NOperationResult::kUnsupportedMethod:
////          s = kUnsupportedMethod;
////          break;
////        case NArchive::NExtract::NOperationResult::kCRCError:
////          s = kCRCFailed;
////          break;
////        case NArchive::NExtract::NOperationResult::kDataError:
////          s = kDataError;
////          break;
////        case NArchive::NExtract::NOperationResult::kUnavailable:
////          s = kUnavailableData;
////          break;
////        case NArchive::NExtract::NOperationResult::kUnexpectedEnd:
////          s = kUnexpectedEnd;
////          break;
////        case NArchive::NExtract::NOperationResult::kDataAfterEnd:
////          s = kDataAfterEnd;
////          break;
////        case NArchive::NExtract::NOperationResult::kIsNotArc:
////          s = kIsNotArc;
////          break;
////        case NArchive::NExtract::NOperationResult::kHeadersError:
////          s = kHeadersError;
////          break;
////      }
////      if (s) {
////        Print("Error : ");
////        Print(s);
////      } else {
////        char temp[16];
////        ConvertUInt32ToString(operationResult, temp);
////        Print("Error #");
////        Print(temp);
////      }
////    }
////  }
////  std::wregex filtInf(_fnMatch, std::regex_constants::icase);
////  std::wsmatch m;
////  std::wstring expFN = _filePath.GetBuf();
////  if (std::regex_search(expFN, m, filtInf) && !_processedFileInfo.isDir &&
////      file_index != -1) {
////    // PrintNewLine();
////    vecBuf fBuf;
////    fBuf.fIndex = file_index;
////    fBuf.fPath = _filePath;
////    file_data.shrink_to_fit();
////    uint8_t bom = check_bom(file_data.c_str(), file_data.size());
////    if (bom) {
////      if (bom == 4) {  // UTF16-LE
////        fBuf.fData = convu16le.from_bytes(
////            reinterpret_cast<const char*>(&file_data[0]),
////            reinterpret_cast<const char*>(&file_data[0] +
/// file_data.size())); /        if (fBuf.fData.at(0) == L'\xFEFF') { /
/// fBuf.fData.replace(0, 1, L" "); /        } / fBuf.fData.shrink_to_fit(); / }
/// else if (bom == 1) { /        fBuf.fData = s2ws(file_data.c_str() + 3); / }
/// else { /        assert(FALSE); /      } /    } else { /      fBuf.fData =
/// s2ws(file_data); /    } /    _vBuf.emplace_back(fBuf); / vecBufReset(fBuf);
////    // Print(", Capt: ");
////    // Print(_filePath);
////    // PrintNewLine();
////  } else {
////    // cout<<'\r';
////    // Print(", Skip: ");
////    // Print(_filePath);
////  }
////  file_data.clear();
////  file_data.shrink_to_fit();
////  return S_OK;
////}
////
////
////void CArchiveExtractCallbackMem::Init(
////    IInArchive* archiveHandler,
////    const wchar_t* fnMatch) {  //,const wchar_t* arcBaseName){
////  NumErrors = 0;
////  _archiveHandler = archiveHandler;
////  _fnMatch = fnMatch;
////  //_arcBaseName=arcBaseName;
////}
////
////STDMETHODIMP CArchiveExtractCallbackMem::SetTotal(UInt64 /* size */) {
////  return S_OK;
////}
////
////STDMETHODIMP CArchiveExtractCallbackMem::SetCompleted(
////    const UInt64* /* completeValue */) {
////  return S_OK;
////}
////
////STDMETHODIMP CArchiveExtractCallbackMem::GetStream(
////    UInt32 index, ISequentialOutStream** outStream, Int32 askExtractMode) {
////  *outStream = NULL;
////  file_index = (UInt32)-1;
////  askExtractMode = 0;
////  {
////    // Get Name
////    NCOM::CPropVariant prop;
////    RINOK(_archiveHandler->GetProperty(index, kpidPath, &prop));
////
////    UString fullPath;
////    if (prop.vt == VT_EMPTY)
////      fullPath = kEmptyFileAlias;
////    else {
////      if (prop.vt != VT_BSTR) return E_FAIL;
////      fullPath = prop.bstrVal;
////    }
////    _filePath = fullPath;
////  }
////
////  //{
////  //  // Get Attrib
////  //    NCOM::CPropVariant prop;
////  //    RINOK(_archiveHandler->GetProperty(index,kpidAttrib,&prop));
////  //    if(prop.vt==VT_EMPTY){
////  //        _processedFileInfo.Attrib=0;
////  //        _processedFileInfo.AttribDefined=false;
////  //    } else{
////  //        if(prop.vt!=VT_UI4)
////  //            return E_FAIL;
////  //        _processedFileInfo.Attrib=prop.ulVal;
////  //        _processedFileInfo.AttribDefined=true;
////  //    }
////  //}
////
////  RINOK(IsArchiveItemFolder(_archiveHandler, index,
///_processedFileInfo.isDir)); /  if (_processedFileInfo.isDir) { /    return
/// S_OK; /  } /  file_index = index;
////
////  //{
////  //  // Get Modified Time
////  //    NCOM::CPropVariant prop;
////  //    RINOK(_archiveHandler->GetProperty(index,kpidMTime,&prop));
////  //    _processedFileInfo.MTimeDefined=false;
////  //    switch(prop.vt){
////  //        case VT_EMPTY:
////  //          // _processedFileInfo.MTime = _utcMTimeDefault;
////  //            break;
////  //        case VT_FILETIME:
////  //            _processedFileInfo.MTime=prop.filetime;
////  //            _processedFileInfo.MTimeDefined=true;
////  //            break;
////  //        default:
////  //            return E_FAIL;
////  //    }
////
////  //}
////  UInt64 newFileSize;
////  {
////    // Get Size
////    NCOM::CPropVariant prop;
////    RINOK(_archiveHandler->GetProperty(index, kpidSize, &prop));
////    // UInt64 newFileSize;
////    /* bool newFileSizeDefined = */ ConvertPropVariantToUInt64(prop,
////                                                               newFileSize);
////  }
////  file_data.clear();
////  file_data.reserve(newFileSize);
////  *outStream = this;
////  // AddRef();
////  //{
////  //   // Create folders for file
////  //     int slashPos=_filePath.ReverseFind_PathSepar();
////  //     if(slashPos>=0)
////  // CreateComplexDir(_directoryPath+us2fs(_filePath.Left(slashPos))); /  //
///}
////
////  // FString fullProcessedPath=_directoryPath+us2fs(_filePath);
////  //_diskFilePath=fullProcessedPath;
////
////  // if(_processedFileInfo.isDir){
////  //     CreateComplexDir(fullProcessedPath);
////  // } else{
////  //     NFind::CFileInfo fi;
////  //     if(fi.Find(fullProcessedPath)){
////  //         if(!DeleteFileAlways(fullProcessedPath)){
////  //             //PrintError("Can not delete output
/// file",fullProcessedPath); /  //             return E_ABORT; /  //         }
////  //     }
////
////  //    _outFileStreamSpec=new COutFileStream;
////  //    CMyComPtr<ISequentialOutStream> outStreamLoc(_outFileStreamSpec);
////  //    if(!_outFileStreamSpec->Open(fullProcessedPath,CREATE_ALWAYS)){
////  //        //PrintError("Can not open output file",fullProcessedPath);
////  //        return E_ABORT;
////  //    }
////  //    _outFileStream=outStreamLoc;
////  //    *outStream=outStreamLoc.Detach();
////  //}
////  return S_OK;
////}
//
//// STDMETHODIMP CArchiveExtractCallbackMem::PrepareOperation(Int32
//// askExtractMode){
////     _extractMode=false;
////     switch(askExtractMode){
////         case NArchive::NExtract::NAskMode::kExtract:  _extractMode=true;
////         break;
////     };
////     switch(askExtractMode){
////         case NArchive::NExtract::NAskMode::kExtract:
////         Print(kExtractingString); break; case
////         NArchive::NExtract::NAskMode::kTest:  Print(kTestingString); break;
////         case NArchive::NExtract::NAskMode::kSkip:  Print(kSkippingString);
////         break;
////     };
////     Print(_filePath);
////     return S_OK;
//// }
//

//
// std::wstring string_to_wstring(const std::string& text) {
//  return std::wstring(text.begin(), text.end());
//}
//
//
////NDLL::CLibrary lib;
//
//
// long getFLen(std::string fPath) {
//  FILE* fp = fopen(fPath.c_str(), "r");
//  fseek(fp, 0, SEEK_END);
//  long length = ftell(fp);
//  fclose(fp);
//  return length;
//}
//
//
//
// template <typename T>
// std::pair<bool, int> findInVector(const std::vector<T>& vecOfElements,
//                                  const T& element) {
//  std::pair<bool, int> result;
//
//  // Find given element in vector
//  auto it = std::find(vecOfElements.begin(), vecOfElements.end(), element);
//
//  if (it != vecOfElements.end()) {
//    result.second = distance(vecOfElements.begin(), it);
//    result.first = true;
//  } else {
//    result.first = false;
//    result.second = -1;
//  }
//
//  return result;
//}
//
// bool ciWstrComp(std::wstring& str1, std::wstring& str2) {
//  return ((str1.size() == str2.size()) &&
//          std::equal(str1.begin(), str1.end(), str2.begin(),
//                     [](wchar_t& c1, wchar_t& c2) {
//                       return (c1 == c2 ||
//                               std::toupper(c1) == std::toupper(c2));
//                     }));
//}
//
//
// std::string ws2s(const std::wstring& wstr) {
//  using convert_typeX = std::codecvt_utf8<wchar_t>;
//  std::wstring_convert<convert_typeX, wchar_t> converterX;
//
//  return converterX.to_bytes(wstr);
//}
//
//// trim from start (in place)
// static inline void ltrim(std::string& s) {
//   s.erase(s.begin(), std::find_if(s.begin(), s.end(),
//                                   [](int ch) { return !std::isspace(ch); }));
// }
//
//// trim from end (in place)
// static inline void rtrim(std::string& s) {
//   s.erase(std::find_if(s.rbegin(), s.rend(),
//                        [](int ch) { return !std::isspace(ch); })
//               .base(),
//           s.end());
// }
//
//// trim from both ends (in place)
// static inline void trim(std::string& s) {
//   ltrim(s);
//   rtrim(s);
// }
//
//// trim from start (copying)
// static inline std::string ltrim_copy(std::string s) {
//   ltrim(s);
//   return s;
// }
//
//// trim from end (copying)
// static inline std::string rtrim_copy(std::string s) {
//   rtrim(s);
//   return s;
// }
//
//// trim from start (in place)
// static inline void ltrim(std::wstring& s) {
//   s.erase(s.begin(), std::find_if(s.begin(), s.end(),
//                                   [](int ch) { return !std::iswspace(ch);
//                                   }));
// }
//
//// trim from end (in place)
// static inline void rtrim(std::wstring& s) {
//   s.erase(std::find_if(s.rbegin(), s.rend(),
//                        [](int ch) { return !std::iswspace(ch); })
//               .base(),
//           s.end());
// }
//
//// trim from both ends (in place)
// static inline void trim(std::wstring& s) {
//   ltrim(s);
//   rtrim(s);
// }
//
//// trim from start (copying)
// static inline std::wstring ltrim_copy(std::wstring s) {
//   ltrim(s);
//   return s;
// }
//
//// trim from end (copying)
// static inline std::wstring rtrim_copy(std::wstring s) {
//   rtrim(s);
//   return s;
// }
//
// std::string frstr(std::ifstream* file) {
//   char Char;
//   std::string Str = "";
//   while (file->read(&Char, sizeof(char))) {
//     Str += Char;
//     if (Char == '\0') return Str;
//   }
//   return Str;
// }
//

//
// void dbFGet(std::ifstream& inFile, std::wstring& wstr, uint16_t& i,
//             char*& cstr) {
//   inFile.read(reinterpret_cast<char*>(&i), sizeof(uint16_t));
//   cstr = (char*)realloc(NULL, i * sizeof(char));
//   // cstr=new char(i);
//   inFile.read(cstr, (i * sizeof(wchar_t)) + 1);
//   wstr.assign(reinterpret_cast<wchar_t*>(cstr), i);
// }
//

//// https://www.geeksforgeeks.org/compare-two-version-numbers/
// int versionCompare(std::wstring v1, std::wstring v2) {
//   // vnum stores each numeric
//   // part of version
//   int vnum1 = 0, vnum2 = 0;
//
//   // loop until both string are
//   // processed
//   for (int i = 0, j = 0; (i < v1.length() || j < v2.length());) {
//     // storing numeric part of
//     // version 1 in vnum1
//     while (i < v1.length() && v1[i] != '.') {
//       vnum1 = vnum1 * 10 + (v1[i] - '0');
//       i++;
//     }
//
//     // storing numeric part of
//     // version 2 in vnum2
//     while (j < v2.length() && v2[j] != '.') {
//       vnum2 = vnum2 * 10 + (v2[j] - '0');
//       j++;
//     }
//
//     if (vnum1 > vnum2) return 1;
//     if (vnum2 > vnum1) return -1;
//
//     // if equal, reset variables and
//     // go for next numeric part
//     vnum1 = vnum2 = 0;
//     i++;
//     j++;
//   }
//   return 0;
// }
//

// void wFDB(std::ofstream& of, uint8_t& i) { of.write((char*)&i, sizeof(i)); }
// void wFDB(std::ofstream& of, uint16_t& i) { of.write((char*)&i, sizeof(i)); }
///* void wFDB(ofstream& of, uint32_t& i) {
//    of.write((char*)&i,sizeof(i));
//}*/
// void wFDB(std::ofstream& of, size_t i) {
//  uint32_t l = i;
//  of.write((char*)&l, sizeof(l));
//}
//

bool saveDPDB(dpdb& db){
    std::wstring archiveName=(L"DriverPacks\\"+db.dpBaseName+L".ddb");
    std::ofstream outFile(archiveName.c_str(),std::ios::out|std::ios::binary);
    uint16_t l=(uint16_t)ws2s(db.dbMagic).length();
    outFile.write((char*)ws2s(db.dbMagic).data(),(l+1)*sizeof(char));
    wFDB(outFile,db.dbSpec);
    wFDB(outFile,db.dpBaseName);
    wFDB(outFile,db.dpFileName);
    wFDB(outFile,db.dpVersion);
    wFDB(outFile,db.dbStrings.size());
    for(size_t vi=0; vi<db.dbStrings.size(); ++vi){
        wFDB(outFile,db.dbStrings[vi]);
    }
    wFDB(outFile,db.dbDevices.size());
    for(size_t vi=0; vi<db.dbDevices.size(); ++vi){
        wFDB(outFile,db.dbDevices[vi]);
    }
    wFDB(outFile,db.dbDrivers.size());
    for(ddb::driver d:db.dbDrivers){
        wFDB(outFile,d.fPath);
        wFDB(outFile,d.fName);
        wFDB(outFile,d.drvDate);
        wFDB(outFile,d.drvVer);
        wFDB(outFile,d.drvClass);
        wFDB(outFile,d.drvClassGuid);
        wFDB(outFile,d.drvPlats.size());
        for(std::wstring s:d.drvPlats){
            wFDB(outFile,s);
        }
        wFDB(outFile,d.devs.size());
        for(ddb::driver::dev dv:d.devs){
            wFDB(outFile,dv.desc);
            wFDB(outFile,dv.hwid);
        }
    }
    outFile.close();
    return true;
}


// static FString CmdStringToFString(const char* s) {
//  return us2fs(GetUnicodeString(s));
//}

// bool dpGetInfs(dp& oDP) {
//  Func_CreateObject createObjectFunc =
//      (Func_CreateObject)lib.GetProc("CreateObject");
//  if (!createObjectFunc) {
//    //PrintError("Can not get CreateObject");
//    return false;
//  }
//  CMyComPtr<IInArchive> archive;
//  if (createObjectFunc(&CLSID_Format, &IID_IInArchive, (void**)&archive) !=
//      S_OK) {
//    //PrintError("Can not get class object");
//    return false;
//  }
//  FString archiveName = CmdStringToFString(
//      ws2s(std::wstring(dpsPath) + L"\\" + oDP.dpFileName).c_str());
//  CInFileStream* fileSpec = new CInFileStream;
//  CMyComPtr<IInStream> file = fileSpec;
//  if (!fileSpec->Open(archiveName)) {
//    //PrintError("Can not open archive file", archiveName);
//    return false;
//  }
//  //IArchiveOpenCallback* openCallbackSpec = new CArchiveOpenCallback;
//  CMyComPtr<IArchiveOpenCallback> openCallback;
//  //openCallbackSpec->PasswordIsDefined = false;
//  const UInt64 scanSize = 1 << 23;
//  if (archive->Open(file, &scanSize, openCallback) != S_OK) {
//    //PrintError("Can not open file as archive", archiveName);
//    return false;
//  }
//  CArchiveExtractCallbackMem* extractCallbackSpec =
//      new CArchiveExtractCallbackMem;
//  CMyComPtr<CArchiveExtractCallbackMem> extractCallback(extractCallbackSpec);
//
//  CMyComPtr<IArchiveExtractCallback> extractCallback = extractCallbackSpec;
//  extractCallbackSpec->Init(
//      archive, L"^.*\\.inf$");  // second parameter is output folder path
//  extractCallbackSpec->PasswordIsDefined = false;
//  HRESULT result =
//      archive->Extract(NULL, (UInt32)(Int32)(-1), false, extractCallback);
//  if (result != S_OK) {
//    //PrintError("Extract Error");
//    return false;
//  }
//  // return extractCallbackSpec->_vBuf;
//  oDP.vInfs = extractCallbackSpec->_vBuf;
//  extractCallbackSpec->_vBuf.clear();
//  extractCallbackSpec->_vBuf.shrink_to_fit();
//  return true;
//}

// std::ifstream::pos_type filesize(const char* filename) {
//  std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
//  return in.tellg();
//}

void wFDB(std::ofstream& of,std::wstring& wStr){
    uint16_t l=(((uint16_t)wStr.length()+1)*sizeof(wchar_t));
    of.write((char*)&l,sizeof(l));
    of.write((char*)wStr.data(),l);
}
void wFDB(std::ofstream& of,uint8_t& i){
    of.write((char*)&i,sizeof(i));
}
void wFDB(std::ofstream& of,uint16_t& i){
    of.write((char*)&i,sizeof(i));
}
void wFDB(std::ofstream& of,size_t i){
    uint32_t l=(uint32_t)i;
    of.write((char*)&l,sizeof(l));
}

void getLocalDPs(){
    // Scan DPs dir
    WIN32_FIND_DATAW fdDP;
    LPCWSTR filtPath=L"\\*.7z";
    HANDLE hFind=FindFirstFileW((std::wstring(dpsPath)+filtPath).c_str(),
                                &fdDP);  // FILES
    if(hFind!=INVALID_HANDLE_VALUE){
        do{
            // std::wcout<<data.cFileName<<std::endl;
            localDPs.push_back(fName2DP(fdDP.cFileName));
        } while(FindNextFileW(hFind,&fdDP));
        FindClose(hFind);
    }
}

dp fName2DP(std::wstring fName){
    // wcout<<fName<<L"\n";
    /*wstring text(fName);*/
    dp newDP;
    std::wsmatch m;
    std::wregex re(L"DP_(.*)_(\\d{1,})\\.7z");
    if(std::regex_search(fName,m,re)){
        newDP.dpFileName=fName;
        newDP.dpBaseName=m.str(1);
        newDP.dpVersion=(uint16_t)wcstoul(m.str(2).c_str(),NULL,0);
    }
    return newDP;
}

std::wstring s2ws(const std::string& s,int slength){
    int len;
    if(!slength){
        slength=(int)s.length()+1;
    }
    len=MultiByteToWideChar(CP_ACP,0,s.c_str(),slength,0,0);
    wchar_t* buf=new wchar_t[len];
    MultiByteToWideChar(CP_ACP,0,s.c_str(),slength,buf,len);
    std::wstring r(buf);
    delete[] buf;
    return r;
}

std::string ws2s(const std::wstring& s,int slength){
    int len;
    if(!slength){
        slength=(int)s.length()+1;
    }
    len=WideCharToMultiByte(CP_ACP,0,s.c_str(),slength,0,0,0,0);
    char* buf=new char[len];
    //MultiByteToWideChar(CP_ACP,0,s.c_str(),slength,buf,len);
    len=WideCharToMultiByte(CP_ACP,0,s.c_str(),slength,buf,len,0,0);
    std::string r(buf);
    delete[] buf;
    return r;
}

uint8_t check_bom(const char* data,size_t size){
    if(size>=3){
        if(memcmp(data,UTF_8_BOM,3)==0) return 1;  // L"UTF-8";
    }
    if(size>=4){
        if(memcmp(data,UTF_32_LE_BOM,4)==0) return 2;  // L"UTF-32-LE";
        if(memcmp(data,UTF_32_BE_BOM,4)==0) return 3;  // L"UTF-32-BE";
    }
    if(size>=2){
        if(memcmp(data,UTF_16_LE_BOM,2)==0) return 4;  // L"UTF-16-LE";
        if(memcmp(data,UTF_16_BE_BOM,2)==0) return 5;  // L"UTF-16-BE";
    }
    return 0;  // NULL;
}

bool compareDates(const std::wstring& date1,const std::wstring& date2){
    std::wstring standardizedDate1=standardizeDate(date1);
    std::wstring standardizedDate2=standardizeDate(date2);

    if(standardizedDate1.empty()||standardizedDate2.empty()){
        std::wcerr<<L"Error: Invalid date format."<<std::endl;
        return false;
    }

    return standardizedDate1<standardizedDate2;
}

std::wstring standardizeDate(const std::wstring& date){
    std::wistringstream dateStream(date);
    std::wstring year,month,day;

    if(date.find(L'-')!=
       std::wstring::npos){  // Handling MM-DD-YYYY or YYYY-MM-DD
        std::getline(dateStream,month,L'-');
        std::getline(dateStream,day,L'-');
        std::getline(dateStream,year);

        if(year.length()==4){  // It was MM-DD-YYYY
            return year+(month.length()==1?L"0"+month:month)+
                (day.length()==1?L"0"+day:day);
        } else{  // It was YYYY-MM-DD
            std::swap(year,month);
            return year+(month.length()==1?L"0"+month:month)+
                (day.length()==1?L"0"+day:day);
        }
    } else if(date.find(L'/')!=std::wstring::npos){  // Handling MM/DD/YYYY
        std::getline(dateStream,month,L'/');
        std::getline(dateStream,day,L'/');
        std::getline(dateStream,year);
        return year+(month.length()==1?L"0"+month:month)+
            (day.length()==1?L"0"+day:day);
    }

    // If the format is not recognized, return an empty string to signify an error 
    return L"";
}


#pragma region dpmGenerateDPDB
void trim(std::wstring& s){
    s=std::regex_replace(s,ltrim,L"");
    s=std::regex_replace(s,rtrim,L"");
}

bool vecInfHasSect(std::vector<vecInfSect>& vec,const std::wstring sMatch){
    for(auto&& y:vec){
        std::transform(y.sect.begin(),y.sect.end(),y.sect.begin(),::tolower);
        if(y.sect==sMatch){
            return true;
        }
    }
    return false;
}

bool vecInfSectHasVal(std::vector<vecInfSect>& vec,const std::wstring sMatch,const std::wregex vMatch){
    vecInfSect sect;
    for(auto&& y:vec){
        std::transform(y.sect.begin(),y.sect.end(),y.sect.begin(),::tolower);
        if(y.sect==sMatch){
            sect=y;
        }
    }
    if(!sect.sect.empty()){
        return false;
    }
    for(auto&& y:sect.lines){
        std::transform(y.begin(),y.end(),y.begin(),::tolower);
        if(std::regex_match(y,vMatch)){
            return true;
        }
    }
    return false;
}

bool lineFilter(const std::wstring& line){
    // std::algorithm::trim(line);
    if(line.empty()) return true;
    if(line.size()<=1) return true;
    // wchar_t c=;
    if(line.at(0)==L'\r'||line.at(0)==L';') return true;
    if(line.at(0)==L' '){
        return false;
    }
    return false;
}

void drvReset(ddb::driver& drv){
    drv.reset();
    //drv.drvDate.clear();
    //drv.drvPlats.clear();
    //drv.drvVer.clear();
    //drv.fName.clear();
    //drv.fPath.clear();
    //drv.devs.clear();
    //// drv.devs.shrink_to_fit();
    //// vector<ddb::driver::dev>().swap(drv.devs);
}

bool dpGenDB(dp& oDP){
    if(!oDP.vInfs.size()){
        return false;
    }
    wprintf(L"Processing: %s\r\n",oDP.dpFileName.c_str());
    std::wcmatch match;
    ddb db;
    db.dbMagic=L"~!Infinity.DriverPackDB";
    db.dbSpec=1;
    dpmGenDDB(db,oDP.vInfs);
    oDP.dpDB=dpdb(db);
    oDP.dpDB.dpBaseName=oDP.dpBaseName;
    oDP.dpDB.dpFileName=oDP.dpFileName;
    oDP.dpDB.dpVersion=oDP.dpVersion;
    saveDPDB(oDP.dpDB);
    return true;
}
#pragma endregion dpmGenerateDPDB

#pragma region dpmLoadDPDB
bool dpGetDB(dp& rdp){
    std::wstring sdb=(L"DriverPacks\\"+rdp.dpBaseName+L".ddb");
    std::ifstream ifs(sdb,std::ios::binary|std::ios::ate);
    if(!ifs.is_open()){
        return false;
    }
    std::ifstream::pos_type pos=ifs.tellg();
    std::vector<char> buf(pos);
    ifs.seekg(0,std::ios::beg);
    ifs.read(&buf[0],pos);
    ifs.close();
    //uint16_t l=9;
    uint32_t p=0;
    uint32_t vl=0;
    uint32_t svl=0;
    std::vector<char> vStr;
    std::vector<wchar_t> vwStr;
    std::wstring twStr;
    dbRawRead(buf,9,p,vStr);
    rdp.dpDB.dbMagic=s2ws(std::string(vStr.begin(),vStr.end()));
    dbGetUINT(buf,p,vStr,rdp.dpDB.dbSpec);
    dbGetWStr(buf,p,vStr,rdp.dpDB.dpBaseName);
    dbGetWStr(buf,p,vStr,rdp.dpDB.dpFileName);
    dbGetUINT(buf,p,vStr,rdp.dpDB.dpVersion);
    dbGetUINT(buf,p,vStr,vl);
    rdp.dpDB.dbStrings.reserve(vl);
    while(rdp.dpDB.dbStrings.size()<vl){
        twStr.clear();
        dbGetWStr(buf,p,vStr,twStr);
        rdp.dpDB.dbStrings.push_back(twStr);
    }
    dbGetUINT(buf,p,vStr,vl);
    rdp.dpDB.dbDevices.reserve(vl);
    while(rdp.dpDB.dbDevices.size()<vl){
        twStr.clear();
        dbGetWStr(buf,p,vStr,twStr);
        rdp.dpDB.dbDevices.push_back(twStr);
    }
    dbGetUINT(buf,p,vStr,vl);
    rdp.dpDB.dbDrivers.reserve(vl);
    while(rdp.dpDB.dbDrivers.size()<vl){
        ddb::driver drvr;
        dbGetWStr(buf,p,vStr,drvr.fPath);
        dbGetWStr(buf,p,vStr,drvr.fName);
        dbGetWStr(buf,p,vStr,drvr.drvDate);
        dbGetWStr(buf,p,vStr,drvr.drvVer);
        dbGetWStr(buf,p,vStr,drvr.drvClass);
        dbGetWStr(buf,p,vStr,drvr.drvClassGuid);
        dbGetUINT(buf,p,vStr,svl);
        drvr.drvPlats.reserve(svl);
        while(drvr.drvPlats.size()<svl){
            twStr.clear();
            dbGetWStr(buf,p,vStr,twStr);
            drvr.drvPlats.push_back(twStr);
        }
        dbGetUINT(buf,p,vStr,svl);
        drvr.devs.reserve(svl);
        while(drvr.devs.size()<svl){
            ddb::driver::dev drvd;
            dbGetUINT(buf,p,vStr,drvd.desc);
            dbGetUINT(buf,p,vStr,drvd.hwid);
            drvr.devs.push_back(drvd);
        }
        rdp.dpDB.dbDrivers.push_back(drvr);
    }

    buf.clear();
    buf.shrink_to_fit();
    return true;
}

void dbRawRead(std::vector<char>& buf,uint16_t l,uint32_t& p,std::vector<char>& vStr){
    vStr.clear();
    vStr.resize(l);
    memcpy(&vStr.at(0),&buf.at(p),l);
    p+=l;
}

void dbRawReadW(std::vector<char>& buf,uint16_t l,uint32_t& p,std::vector<wchar_t>& vStr){
    // vStr.clear();
    memcpy(&vStr.at(0),&buf.at(p),l);
    p+=l;
}

void dbGetUINT(std::vector<char>& buf,uint32_t& p,std::vector<char>& vStr,std::uint8_t& i){
    dbRawRead(buf,1,p,vStr);
    i=*reinterpret_cast<const uint8_t*>(&vStr[0]);
}
void dbGetUINT(std::vector<char>& buf,uint32_t& p,std::vector<char>& vStr,std::uint16_t& i){
    dbRawRead(buf,2,p,vStr);
    i=*reinterpret_cast<const uint16_t*>(&vStr[0]);
}

void dbGetUINT(std::vector<char>& buf,uint32_t& p,std::vector<char>& vStr,std::uint32_t& i){
    dbRawRead(buf,4,p,vStr);
    i=*reinterpret_cast<const uint32_t*>(&vStr[0]);
}

void dbGetStr(std::vector<char>& buf,uint32_t& p,std::vector<char>& vStr){
    dbRawRead(buf,2,p,vStr);
    dbRawRead(buf,*reinterpret_cast<const uint16_t*>(&vStr[0]),p,vStr);
}

void dbGetWStr(std::vector<char>& buf,uint32_t& p,std::vector<char>& vStr,std::wstring& wStr){
    dbRawRead(buf,2,p,vStr);
    uint16_t t=(*reinterpret_cast<const uint16_t*>(&vStr[0]));
    std::vector<wchar_t> vwStr;
    vwStr.resize(t/sizeof(wchar_t));
    if(!t){
        dbRawRead(buf,2,p,vStr);
        t=(*reinterpret_cast<const uint16_t*>(&vStr[0]));
        vwStr.resize(t);
    }
    dbRawReadW(buf,t,p,vwStr);
    wStr=std::wstring(vwStr.begin(),vwStr.end()-1);
}
#pragma endregion dpmLoadDPDB


std::wstring ConvertUtf16LeBufferToWString(const char* buffer, size_t size_in_bytes) {
  if (buffer == nullptr || size_in_bytes == 0) {
    return std::wstring();
  }

  size_t offset = 0;

  // Check for BOM (Byte Order Mark)
  if (size_in_bytes >= 2) {
    unsigned char byte1 = static_cast<unsigned char>(buffer[0]);
    unsigned char byte2 = static_cast<unsigned char>(buffer[1]);

    if (byte1 == 0xFF && byte2 == 0xFE) {
      // UTF-16LE BOM detected, skip it
      offset = 2;
    }
  }

  // Calculate the number of wchar_t elements
  size_t num_chars = (size_in_bytes - offset) / sizeof(wchar_t);

  // Ensure that the remaining bytes form complete wchar_t units
  if ((size_in_bytes - offset) % sizeof(wchar_t) != 0) {
    std::cerr << "Warning: Buffer size is not a multiple of wchar_t size. Truncating incomplete character.\n";
  }

  // Reinterpret the buffer as wchar_t*
  const wchar_t* wchar_buffer = reinterpret_cast<const wchar_t*>(buffer + offset);

  // Create a wstring from the wchar_t buffer
  std::wstring result(wchar_buffer, num_chars);

  return result;
}
