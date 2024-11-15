#pragma once
#include <codecvt>
#include <locale>
#include <regex>
#include <string>
#include <vector>
#include <atomic>
#include <memory>
#include <chrono>
#include <Windows.h>

std::string dpmCurlRet;
std::locale dpmLoc;


//std::wstring_convert<std::codecvt_utf16<wchar_t,0x10ffff,std::little_endian>,wchar_t> convu16le;

bool dpmDoUpdate=false;
const char* UTF_16_BE_BOM = "\xFE\xFF";
const char* UTF_16_LE_BOM = "\xFF\xFE";
const char* UTF_8_BOM = "\xEF\xBB\xBF";
const char* UTF_32_BE_BOM = "\x00\x00\xFE\xFF";
const char* UTF_32_LE_BOM = "\xFF\xFE\x00\x00";

// STDMETHODIMP CArchiveExtractCallbackMem::CryptoGetTextPassword(BSTR*
// password){
//     if(!PasswordIsDefined){
//       // You can ask real password here from user
//       // Password = GetPassword(OutStream);
//       // PasswordIsDefined = true;
//         PrintError("Password is not defined");
//         return E_ABORT;
//     }
//     return StringToBstr(Password,password);
// }

class tPerf{
public:
    std::chrono::steady_clock::time_point tStart;
    std::chrono::steady_clock::time_point tEnd;
    std::chrono::duration<double> tElapsed;
    double tMin;
    double tMax;
    double tAvg;
    double tSum;
    double tLast;
    uint32_t iAvg;
    std::wstring sAlias;
    void clear(){
        tElapsed=std::chrono::duration<double>(0);
        tMin=0;
        tMax=0;
        tAvg=0;
        tSum=0;
        iAvg=0;
        tLast=0;
    }
    void reset(){
        clear();
        tStart=std::chrono::high_resolution_clock::now();
    }
    void start(){ tStart=std::chrono::high_resolution_clock::now(); }
    void stat(){
        wprintf(
            L"\"%s\": "
            L"{\"tLast\":%0.4fms,\"tMin\":%0.4fms,\"tMax\":%0.4fms,\"tAvg\":%0."
            L"4fms,\"tSum\":%0.4fms,\"iAvg\":%d}\r\n",
            sAlias.c_str(),tLast,tMin,tMax,tAvg,tSum,iAvg);
    }
    void chkpt(bool doStat=false){
        tEnd=std::chrono::high_resolution_clock::now();
        tElapsed=tEnd-tStart;
        tLast=tElapsed.count()*1000;
        tSum+=tLast;
        iAvg++;
        tAvg=tSum/iAvg;
        if(tMin==0||tLast<tMin) tMin=tLast;
        if(tLast>tMax) tMax=tLast;
        if(doStat) stat();
        tStart=std::chrono::high_resolution_clock::now();
    }
    tPerf(std::wstring alias){
        clear();
        sAlias=alias;
    }
};

//struct vecBuf{
//    uint32_t fIndex=0;
//    std::wstring fPath=L"";
//    std::wstring fData=L"";
//};

struct dpdb: ddb{
    std::wstring dpFileName=L"";
    std::wstring dpBaseName=L"";
    uint16_t dpVersion=0;
    dpdb(){
        dbMagic=L"Inf.DPDB";
        dbSpec=1;
        dpVersion=0;
    }
    dpdb(ddb& db){
        dbMagic=db.dbMagic;
        dbSpec=db.dbSpec;
        dpVersion=0;
        dbStrings=db.dbStrings;
        dbDevices=db.dbDevices;
        dbDrivers=db.dbDrivers;
    }
};

class dp{
public:
    std::wstring dpFileName=L"";
    std::wstring dpBaseName=L"";
    uint16_t dpVersion=0;
    std::vector<vecBuf> vInfs;
    dpdb dpDB;
};

struct dpStrRef{
    std::wstring sRef=L"";
    std::wstring sDef=L"";
    // uint64_t iRef;
};

LPCWSTR dpsu=L"https://download0.driverpack.io/driverpacks/";
std::vector<dp> srvDPs;
std::vector<dp> localDPs;
std::vector<ddb> localDBs;
LPCWSTR dpsPath=L"DriverPacks";

struct vecInfSect{
    std::wstring sect=L"";
    std::vector<std::wstring> lines;
};

struct drvExtract{
    std::wstring dp=L"";
    std::vector<std::wstring> paths;
};


static std::wregex ltrim(L"^\\s+");
static std::wregex rtrim(L"\\s+$");

static std::wregex exp_chwid(
    L"^\"([^\"]*)\"\\s*$");  // Match Inf String
// static std::wregex
// exp_fnp(L"^(.*)[\\\\\/]([^\\\\\/]*\\..*)$");
static std::wregex exp_fnp(L"^(.*)[\\\\/]([^\\\\/]*\\..*)$");
static std::wregex exp_dv(
    L"^driverver\\s*=\\s*(?:(\\d{1,2}[\\/-]\\d{1,2}[\\/"
    L"-]\\d{4})|%[^%]+%)?(?:,\\s*(?:Ver\\s?)?(\\d+(?:\\.?\\d+)+|%[^%]*%)?\\.?"
    L"\\s*)?(?:\\s*;.*)?$");  // Match DriverVer
static std::wregex exp_dvod(
    L"^driverver\\s*=\\s*(\\d{2}\\/\\d{2}\\/"
    L"\\d{4})\\s*(?:\\s*;.*)?$");  // Match DriverVer, only date.
static std::wregex exp_dc(L"^class\\s*=\\s*(.*)?(?:\\s*;.*)?$");  // Match Class
static std::wregex exp_dg(
    L"^classguid\\s*=\\s*(.*)?(?:\\s*;.*)?$");  // Match ClassGuid
static std::wregex exp_mfgm(
    L"^[^=]+=\\s*([^,]+)(?:\\s*(?:,\\s*([^\\r\\n;]+)\\s*)+)?.*");  //(L"^(\".+\"|%[^\\s=]+%)\\s*=\\s*([^,\\s]+)(?:(?:,\\s*([^;\\r]*))+)?(?:[.\\s\\r\\n]+)?$");
////^(\".+\"|[^=]+)=([^,]+)(?:(?:,\\s*([^;]*))+)?(?:\\s*;.*)?$");
static std::wregex exp_mfgd(
    L"^(\".+\"|[^=]+)=[^,]+,\\s*(?:,\\s*)?([^;]*)(?:\\s*;.*)?$");
static std::wregex exp_saqm(
    L"^(?:\"([^=\"]+)\")\\s*=\\s*\"{1,2}?([^=\"]*)\"{1,2}?\\s*$");
static std::wregex exp_sabm(L"^(?:([^=]+))\\s*=\\s*\"*([^=\"]+)\"*\\s*$");
static std::wregex exp_sam(L"^(?:([^=\\s]+))\\s*=\\s*\"*([^=\"]+)\"*\\s*$");
static std::wregex exp_s(
    L"[^\\[\\]]*\\[([^\\[\\]]+)\\][^\\[\\]]*");  // Match Inf Section
static std::wregex exp_sra(
    L"\"?([^=\"]*)\"?=\"*([^=\"]+)\"*$");  // Match Inf String Ref Assignment
static std::wregex ea(
    L"^([^=]+=[^=\\r;]+)(?:[.\\r\\n]+)?.*");  //(L"((?:\\S+)|\"(?:.+)\")\\s*=\\s*((?:\\S+)|(?:(?:,\\s*)?(?:\\S+))+|\"(?:.+)\")\s*");
//// Proper Assignments
static std::wregex exp_sr(L"\\%([^\\s\\%]*)\\%\\s*");  // Match Inf String Ref
static std::wregex exp_inlsrm(L".*(%[^\\s%]+%|\"[^\"]+\").*");
static std::wregex exp_srq(L"^\"([^\"]*)\"\\s*$");  // Match Inf String Ref
static std::wregex exp_dvsm(L"^\\s*driverver\\s*=\\s*.*$",
                            std::regex_constants::icase);
static std::wregex exp_dcsm(L"^ Class=.*$");
static std::wregex exp_dgsm(L"^ ClassGUID=.*$");
static std::wregex exp_inlsr(L"%[^\\s%]+%");
static std::wregex exp_slcm(L"^[\\s\\t]*;.*");
// exp_saqm
// exp_sra
// exp_sam
// exp_sabm

//////////////////////////////////////////////////////////////
// Archive In-Memory Extracting callback class

// class CArchiveExtractCallbackMem : public IArchiveExtractCallback,
//                                    public ICryptoGetTextPassword,
//                                    public ISequentialOutStream,
//                                    public CMyUnknownImp {
//  public:
//   // CArchiveExtractCallbackMem(IInArchive* _archive):
//   // archive(_archive),item_proc(NULL),file_index(-1){}
//
//   // struct IItemProc{
//   //     virtual bool OnOk(const char* name,const t_filestats& stat,const
//   //     std::string& data)=0;
//   // };
//   //MY_UNKNOWN_IMP1(ICryptoGetTextPassword)
//
//   // IProgress
//   STDMETHOD(SetTotal)(UInt64 size);
//   STDMETHOD(SetCompleted)(const UInt64* completeValue);
//   // STDMETHOD(SetCompleted)(const UInt64* completeValue){return S_OK;}
//
//   // IArchiveExtractCallback
//   STDMETHOD(GetStream)
//   (UInt32 index, ISequentialOutStream** outStream, Int32 askExtractMode);
//   // STDMETHOD(GetStream)(UInt32 index,ISequentialOutStream** outStream);
//   // STDMETHOD(PrepareOperation)(Int32 askExtractMode);
//   STDMETHOD(PrepareOperation)(Int32 askExtractMode) {
//     askExtractMode = 0;
//     return S_OK;
//   }
//   // STDMETHOD(PrepareOperation)(){ return S_OK; }
//   STDMETHOD(SetOperationResult)(Int32 resultEOperationResult);
//
//   // ICryptoGetTextPassword
//   // STDMETHOD(CryptoGetTextPassword)(BSTR* aPassword);
//   // STDMETHOD(CryptoGetTextPassword)(BSTR* password){ return E_ABORT; }
//   STDMETHOD(CryptoGetTextPassword)(BSTR* password) {
//     password = (BSTR*)"";
//     return E_ABORT;
//   }
//   STDMETHOD(Write)(const void* data, UInt32 size, UInt32* processedSize) {
//     file_data.insert(file_data.length(), (const char*)data, size);
//     if (*processedSize) *processedSize = size;
//     return S_OK;
//   }
//   // t_filestats Stat(UInt32 idx);
//
//   // IItemProc* item_proc;
//   struct vecBuf {
//     UInt32 fIndex;
//     std::wstring fPath;
//     std::wstring fData;
//   };
//   void vecBufReset(vecBuf& vec) {
//     // std::wstring().swap(vec.fData);
//     vec.fData.clear();
//     vec.fData.shrink_to_fit();
//     vec.fIndex = 0;
//     vec.fPath = std::wstring();
//   }
//
//  private:
//   CMyComPtr<IInArchive> _archiveHandler;
//   const wchar_t* _fnMatch;
//   std::string file_data;
//   // FString _directoryPath;  // !!! Change to regexp match !!!
//   UString _filePath;  // name inside arcvhive
//   // FString _diskFilePath;   // !!! change to dest vector buffer !!!
//   bool _extractMode;
//   UInt32 file_index;
//   struct CProcessedFileInfo {
//     FILETIME MTime;
//     UInt32 Attrib;
//     bool isDir;
//     bool AttribDefined;
//     bool MTimeDefined;
//   } _processedFileInfo;
//   COutFileStream* _outFileStreamSpec;
//   CMyComPtr<ISequentialOutStream> _outFileStream;
//   // const wchar_t* _arcBaseName;
//  public:
//   void Init(IInArchive* archiveHandler,
//             const wchar_t* fnMatch);  //,const wchar_t* arcBaseName);
//   std::vector<vecBuf> _vBuf;
//   UInt64 NumErrors;
//   bool PasswordIsDefined;
//   UString Password;
//   CArchiveExtractCallbackMem() : PasswordIsDefined(false) {}
// };

// Structure to store extracted .inf file information

void getLocalDPs();
dp fName2DP(std::wstring fName);
//uint8_t check_bom(const char* data,size_t size);
bool dpGetDB(dp& rdp);
void dbRawRead(std::vector<char>& buf,uint16_t l,uint32_t& p,std::vector<char>& vStr);
void dbRawReadW(std::vector<char>& buf,uint16_t l,uint32_t& p,std::vector<wchar_t>& vStr);
void dbGetUINT(std::vector<char>& buf,uint32_t& p,std::vector<char>& vStr,std::uint8_t& i);
void dbGetUINT(std::vector<char>& buf,uint32_t& p,std::vector<char>& vStr,std::uint16_t& i);
void dbGetUINT(std::vector<char>& buf,uint32_t& p,std::vector<char>& vStr,std::uint32_t& i);
void dbGetStr(std::vector<char>& buf,uint32_t& p,std::vector<char>& vStr);
void dbGetWStr(std::vector<char>& buf,uint32_t& p,std::vector<char>& vStr,std::wstring& wStr);
std::wstring standardizeDate(const std::wstring& date);
bool compareDates(const std::wstring& date1,const std::wstring& date2);
bool dpGenDB(dp& oDP);
void trim(std::wstring& s);
bool vecInfSectHasVal(std::vector<vecInfSect>& vec,const std::wstring sMatch,const std::wregex vMatch);
bool vecInfHasSect(std::vector<vecInfSect>& vec,const std::wstring sMatch);
bool lineFilter(const std::wstring& line);
void drvReset(ddb::driver& drv);
bool saveDPDB(dpdb& db);
void wFDB(std::ofstream& of,std::wstring& wStr);
void wFDB(std::ofstream& of,uint8_t& i);
void wFDB(std::ofstream& of,uint16_t& i);
void wFDB(std::ofstream& of,size_t i);
