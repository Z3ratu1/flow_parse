#include <iostream>
#include<fstream>
#include <cstring>
#include"base_type.h"
#include"pcap.h"
#include"MySQLConnector.h"
using namespace std;

extern char* jsonFileName;
int main(int argc, char* argv[])
{
    char* pcapFileName;
    jsonFileName = argv[1];
    pcapFileName = argv[2];
    cout << "pcapFile: " << pcapFileName;
    cout << "json_file: " << jsonFileName << endl;
    parsePcapFile(pcapFileName);
    return 0;
}
