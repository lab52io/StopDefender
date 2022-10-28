#pragma once
#include <windows.h>
#include <iostream>
#include <tchar.h>

using namespace std;

#ifdef UNICODE
#define get_username  get_usernameW
#else
#define get_username  get_usernameA
#endif 

#define DEF_SERVICES_COUNT 5

const PCTSTR DefenderServices[] = {
	TEXT("WdFilter"), // Windows Defender Disk inspection Minifilter
	TEXT("wscsvc"), // Windows Security Center
	TEXT("WinDefend"), // Microsoft Defender Antivirus Service
	TEXT("Sense"), // Windows Defender Advanced Threat Protection Service
	TEXT("WdNisSvc") // Microsoft Defender Antivirus Network Inspection Service
};

wstring get_usernameW();
string get_usernameA();
BOOL StopDefenderService();
int GetProcessByName(PCTSTR name);