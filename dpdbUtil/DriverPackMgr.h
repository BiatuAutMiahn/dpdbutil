#pragma once


struct vecBuf{
    uint32_t fIndex=0;
    std::wstring fPath=L"";
    std::wstring fData=L"";
};

// DB Binary:
// Signature
class ddb{
public:
    class driver{
    public:
        class dev{
        public:
            uint32_t hwid=0;
            uint32_t desc=0;
        };
        std::wstring fPath=L"";              // drivers\viostor\amd64
        std::wstring drvClass=L"";           // System
        std::wstring drvClassGuid=L"";       // {4d36e97d-e325-11ce-bfc1-08002be10318}
        std::wstring fName=L"";              // driver.inf
        std::wstring drvDate=L"";            // YYYY/MM/DD
        std::wstring drvVer=L"";             // 0[.0[.0[.0]]]
        std::vector<std::wstring> drvPlats;  // nt[Architecture][.[OSMajorVersion][.[OSMinorVersion][.[ProductType][.[SuiteMask][.[BuildNumber]]]]]
        std::vector<dev> devs;
        void reset(){
            drvDate.clear();
            drvPlats.clear();
            drvVer.clear();
            fName.clear();
            fPath.clear();
            devs.clear();
        };
    };
    std::wstring dbMagic=L"";
    uint8_t dbSpec=0;
    std::vector<std::wstring> dbStrings;
    std::vector<std::wstring> dbDevices;
    std::vector<driver> dbDrivers;
};

struct devInfo{
    struct driver{
        std::wstring dp=L"";
        std::wstring fPath=L"";         // drivers\viostor\amd64
        std::wstring fName=L"";         // driver.inf
        std::wstring drvClass=L"";      // System
        std::wstring drvClassGuid=L"";  // {4d36e97d-e325-11ce-bfc1-08002be10318}
        std::wstring drvDate=L"";       // YYYY/MM/DD
        std::wstring drvVer=L"";        // 0[.0[.0[.0]]]
        std::vector<std::wstring> hwidMatch;
        std::vector<std::wstring> drvPlats;  // nt[Architecture][.[OSMajorVersion][.[OSMinorVersion][.[ProductType][.[SuiteMask][.[BuildNumber]]]]]
    };
    std::wstring desc=L"";
    std::wstring devClass=L"";
    std::wstring devClassGuid=L"";
    driver drvLocal;
    std::vector<std::wstring> hwids;
    std::vector<std::wstring> chwids;
    std::vector<driver> drivers;
};

struct devMatch{
    // uint32_t iDev;
    std::wstring devId=L"";
    std::vector<devInfo::driver> drivers;
    std::vector<uint32_t> iDevs;
};

struct drvList{
    std::vector<std::wstring> paths;
};


extern int dpmMain();
extern bool dpmGenDDB(ddb& db,std::vector<vecBuf>& fList);
extern bool dpmWriteDDB(ddb& db,std::wstring ddpPath);
extern bool dpmReadDDB(ddb& db,std::wstring ddbPath);
extern bool dpmGetSysDevs(std::vector<devInfo>& sysDevs);
extern bool dpmMatchDevs(std::vector<devInfo>& sysDevs,ddb& db,std::vector<std::wstring> &devMatches);
extern std::string ws2s(const std::wstring& s, int slength = 0);
extern std::wstring s2ws(const std::string& s, int slength = 0);
extern uint8_t check_bom(const char* data, size_t size);
extern std::wstring ConvertUtf16LeBufferToWString(const char* buffer, size_t size_in_bytes);