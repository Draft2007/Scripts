#include <Windows.h>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <iostream>
using namespace std;

SERVICE_STATUS        g_ServiceStatus = {0};

SERVICE_STATUS_HANDLE g_StatusHandle = NULL;

HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;

VOID WINAPI ServiceMain (DWORD argc, LPTSTR *argv);

VOID WINAPI ServiceCtrlHandler (DWORD);

DWORD WINAPI ServiceWorkerThread (LPVOID lpParam);

#define SERVICE_NAME  _T("El Jefe Service Starter")

int _tmain (int argc, TCHAR *argv[])

{
	FILE *f = fopen("servicelog.txt", "w");
	const char *text = "EL Jefe Service Starter: Main: Entry";
	fclose(f);
    OutputDebugString(_T("EL Jefe Service Starter: Main: Entry"));

    SERVICE_TABLE_ENTRY ServiceTable[] = 

    {

        {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION) ServiceMain},

        {NULL, NULL}

    };

    if (StartServiceCtrlDispatcher (ServiceTable) == FALSE)

    {
		FILE *f = fopen("servicelog.txt", "w");
		const char *text = "El Jefe Service: Main: StartServiceCtrlDispatcher returned error";
		fclose(f);
		OutputDebugString(_T("El Jefe Service: Main: StartServiceCtrlDispatcher returned error"));

       return GetLastError ();

    }

	FILE *f = fopen("servicelog.txt", "w");
	const char *text = "El Jefe Service: Main: Exit\n";
	fclose(f);
    OutputDebugString(_T("El Jefe Service: Main: Exit"));

    return 0;

}

VOID WINAPI ServiceMain (DWORD argc, LPTSTR *argv)

{

    DWORD Status = E_FAIL;

	FILE *f = fopen("servicelog.txt", "w");
	const char *text = "El Jefe Service: ServiceMain: Entry\n";
	fclose(f);
    OutputDebugString(_T("El Jefe Service: ServiceMain: Entry"));

    g_StatusHandle = RegisterServiceCtrlHandler (SERVICE_NAME, ServiceCtrlHandler);

    if (g_StatusHandle == NULL) 

    {
		FILE *f = fopen("servicelog.txt", "w");
		const char *text = "El Jefe Service: ServiceMain: RegisterServiceCtrlHandler returned error\n";
		fclose(f);

        OutputDebugString(_T("El Jefe Service: ServiceMain: RegisterServiceCtrlHandler returned error"));

        goto EXIT;

    }

    // Tell the service controller we are starting

    ZeroMemory (&g_ServiceStatus, sizeof (g_ServiceStatus));

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;

    g_ServiceStatus.dwControlsAccepted = 0;

    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;

    g_ServiceStatus.dwWin32ExitCode = 0;

    g_ServiceStatus.dwServiceSpecificExitCode = 0;

    g_ServiceStatus.dwCheckPoint = 0;

    if (SetServiceStatus (g_StatusHandle, &g_ServiceStatus) == FALSE) 

    {
	
		FILE *f = fopen("servicelog.txt", "w");
		const char *text = "El Jefe Service: ServiceMain: SetServiceStatus returned error\n";
		fclose(f);
        OutputDebugString(_T("El Jefe Service: ServiceMain: SetServiceStatus returned error"));

    }

    /* 

     * Perform tasks neccesary to start the service here

     */

	FILE *f = fopen("servicelog.txt", "w");
	const char *text = "El Jefe Service: ServiceMain: Performing Service Start Operations\n";
	fclose(f);
    OutputDebugString(_T("El Jefe Service: ServiceMain: Performing Service Start Operations"));

    // Create stop event to wait on later.

    g_ServiceStopEvent = CreateEvent (NULL, TRUE, FALSE, NULL);

    if (g_ServiceStopEvent == NULL) 

    {
		FILE *f = fopen("servicelog.txt", "w");
		const char *text = "El Jefe Service: ServiceMain: CreateEvent(g_ServiceStopEvent) returned error\n";
		fclose(f);
        OutputDebugString(_T("El Jefe Service: ServiceMain: CreateEvent(g_ServiceStopEvent) returned error"));


        g_ServiceStatus.dwControlsAccepted = 0;

        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;

        g_ServiceStatus.dwWin32ExitCode = GetLastError();

        g_ServiceStatus.dwCheckPoint = 1;



        if (SetServiceStatus (g_StatusHandle, &g_ServiceStatus) == FALSE)

	    {
			FILE *f = fopen("servicelog.txt", "w");
			const char *text = "El Jefe Service: ServiceMain: SetServiceStatus returned error\n";
			fclose(f);
		    OutputDebugString(_T("El Jefe Service: ServiceMain: SetServiceStatus returned error"));

	    }

        goto EXIT; 

    }    

    // Tell the service controller we are started

    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;

    g_ServiceStatus.dwWin32ExitCode = 0;

    g_ServiceStatus.dwCheckPoint = 0;



    if (SetServiceStatus (g_StatusHandle, &g_ServiceStatus) == FALSE)

    {
		FILE *f = fopen("servicelog.txt", "w");
		const char *text = "El Jefe Service: ServiceMain: SetServiceStatus returned error\n";
		fclose(f);
	    OutputDebugString(_T("El Jefe Service: ServiceMain: SetServiceStatus returned error"));

    }

    // Start the thread that will perform the main task of the service

    HANDLE hThread = CreateThread (NULL, 0, ServiceWorkerThread, NULL, 0, NULL);

	FILE *f = fopen("servicelog.txt", "w");
	const char *text = "El Jefe Service: ServiceMain: Waiting for Worker Thread to complete\n";
	fclose(f);

    OutputDebugString(_T("El Jefe Service: ServiceMain: Waiting for Worker Thread to complete"));

    // Wait until our worker thread exits effectively signaling that the service needs to stop

    WaitForSingleObject (hThread, INFINITE);

	FILE *f = fopen("servicelog.txt", "w");
	const char *text = "El Jefe Service: ServiceMain: Worker Thread Stop Event signaled\n";
	fclose(f);
    OutputDebugString(_T("El Jefe Service: ServiceMain: Worker Thread Stop Event signaled"));

    /* 

     * Perform any cleanup tasks

     */
	FILE *f = fopen("servicelog.txt", "w");
	const char *text = "El Jefe Service: ServiceMain: Performing Cleanup Operations\n";
	fclose(f);
    OutputDebugString(_T("El Jefe Service: ServiceMain: Performing Cleanup Operations"));

    CloseHandle (g_ServiceStopEvent);

    g_ServiceStatus.dwControlsAccepted = 0;

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;

    g_ServiceStatus.dwWin32ExitCode = 0;

    g_ServiceStatus.dwCheckPoint = 3;

    if (SetServiceStatus (g_StatusHandle, &g_ServiceStatus) == FALSE)

    {
		FILE *f = fopen("servicelog.txt", "w");
		const char *text = "El Jefe Service: ServiceMain: SetServiceStatus returned error\n";
		fclose(f);	
	    OutputDebugString(_T("El Jefe Service: ServiceMain: SetServiceStatus returned error"));

    }

    EXIT:
	FILE *f = fopen("servicelog.txt", "w");
	const char *text = "El Jefe Service: ServiceMain: Exit\n";
	fclose(f);
    OutputDebugString(_T("El Jefe Service: ServiceMain: Exit"));
    return;

}

VOID WINAPI ServiceCtrlHandler (DWORD CtrlCode)

{
	FILE *f = fopen("servicelog.txt", "w");
	const char *text = "El Jefe Service: ServiceCtrlHandler: Entry\n";
	fclose(f);
    OutputDebugString(_T("El Jefe Service: ServiceCtrlHandler: Entry"));

    switch (CtrlCode) 

	{

     case SERVICE_CONTROL_STOP :
		FILE *f = fopen("servicelog.txt", "w");
		const char *text = "El Jefe Service: ServiceCtrlHandler: SERVICE_CONTROL_STOP Request\n";
		fclose(f);
        OutputDebugString(_T("El Jefe Service: ServiceCtrlHandler: SERVICE_CONTROL_STOP Request"));



        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)

           break;

        /* 

         * Perform tasks neccesary to stop the service here 

         */        

        g_ServiceStatus.dwControlsAccepted = 0;

        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;

        g_ServiceStatus.dwWin32ExitCode = 0;

        g_ServiceStatus.dwCheckPoint = 4;

        if (SetServiceStatus (g_StatusHandle, &g_ServiceStatus) == FALSE)

		{
			FILE *f = fopen("servicelog.txt", "w");
			const char *text = "El Jefe Service: ServiceCtrlHandler: SetServiceStatus returned error\n";
			fclose(f);
			OutputDebugString(_T("El Jefe Service: ServiceCtrlHandler: SetServiceStatus returned error"));

		}
        // This will signal the worker thread to start shutting down

     SetEvent (g_ServiceStopEvent);
     break;
     default:
     break;
    }

	FILE *f = fopen("servicelog.txt", "w");
	const char *text = "El Jefe Service: ServiceCtrlHandler: Exit\n";
	fclose(f);
    OutputDebugString(_T("El Jefe Service: ServiceCtrlHandler: Exit"));

}

DWORD WINAPI ServiceWorkerThread (LPVOID lpParam)

{	
	DWORD dwType = REG_SZ;
	HKEY hKey = 0;
	char value[1024];
	DWORD value_length = 1024;
	const char* subkey = "SOFTWARE\\Immunity Inc\\El Jefe";
	RegOpenKey(HKEY_LOCAL_MACHINE,subkey,&hKey);
	RegQueryValueEx(hKey, "El Jefe", NULL, &dwType, (LPBYTE)&value, &value_length);
	LPCSTR strval = value;

	FILE *f = fopen("servicelog.txt", "w");
	const char *text = "El Jefe Service: ServiceWorkerThread: Entry\n";
	fclose(f);
    OutputDebugString(_T("El Jefe Service: ServiceWorkerThread: Entry"));
	HANDLE ph;
	STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

	CreateProcess(strval, NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

	FILE *f = fopen("servicelog.txt", "w");
	const char *text = "El Jefe Service: ServiceWorkerThread: Process should be made\n";
	fclose(f);
	OutputDebugString(_T("El Jefe Service: ServiceWorkerThread: Process should be made"));
    //  Periodically check if the service has been requested to stop

    while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0)

    {        

        /* 

         * Perform main service function here

         */

	Sleep(1000);
    }


	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	FILE *f = fopen("servicelog.txt", "w");
	const char *text = "El Jefe Service: ServiceWorkerThread: Exit\n";
	fclose(f);
    OutputDebugString(_T("El Jefe Service: ServiceWorkerThread: Exit"));

	ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);

	TerminateProcess(ph,-1);

    return ERROR_SUCCESS;

}