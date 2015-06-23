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

    OutputDebugString(_T("EL Jefe Service Starter: Main: Entry"));

    SERVICE_TABLE_ENTRY ServiceTable[] = 

    {

        {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION) ServiceMain},

        {NULL, NULL}

    };



    if (StartServiceCtrlDispatcher (ServiceTable) == FALSE)

    {

       OutputDebugString(_T("My Sample Service: Main: StartServiceCtrlDispatcher returned error"));

       return GetLastError ();

    }



    OutputDebugString(_T("My Sample Service: Main: Exit"));

    return 0;

}





VOID WINAPI ServiceMain (DWORD argc, LPTSTR *argv)

{

    DWORD Status = E_FAIL;



    OutputDebugString(_T("My Sample Service: ServiceMain: Entry"));



    g_StatusHandle = RegisterServiceCtrlHandler (SERVICE_NAME, ServiceCtrlHandler);



    if (g_StatusHandle == NULL) 

    {

        OutputDebugString(_T("My Sample Service: ServiceMain: RegisterServiceCtrlHandler returned error"));

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

        OutputDebugString(_T("My Sample Service: ServiceMain: SetServiceStatus returned error"));

    }



    /* 

     * Perform tasks neccesary to start the service here

     */

    OutputDebugString(_T("My Sample Service: ServiceMain: Performing Service Start Operations"));



    // Create stop event to wait on later.

    g_ServiceStopEvent = CreateEvent (NULL, TRUE, FALSE, NULL);

    if (g_ServiceStopEvent == NULL) 

    {

        OutputDebugString(_T("My Sample Service: ServiceMain: CreateEvent(g_ServiceStopEvent) returned error"));



        g_ServiceStatus.dwControlsAccepted = 0;

        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;

        g_ServiceStatus.dwWin32ExitCode = GetLastError();

        g_ServiceStatus.dwCheckPoint = 1;



        if (SetServiceStatus (g_StatusHandle, &g_ServiceStatus) == FALSE)

	    {

		    OutputDebugString(_T("My Sample Service: ServiceMain: SetServiceStatus returned error"));

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

	    OutputDebugString(_T("My Sample Service: ServiceMain: SetServiceStatus returned error"));

    }



    // Start the thread that will perform the main task of the service

    HANDLE hThread = CreateThread (NULL, 0, ServiceWorkerThread, NULL, 0, NULL);



    OutputDebugString(_T("My Sample Service: ServiceMain: Waiting for Worker Thread to complete"));

    // Wait until our worker thread exits effectively signaling that the service needs to stop

    WaitForSingleObject (hThread, INFINITE);

    

    OutputDebugString(_T("My Sample Service: ServiceMain: Worker Thread Stop Event signaled"));

    

    

    /* 

     * Perform any cleanup tasks

     */

    OutputDebugString(_T("My Sample Service: ServiceMain: Performing Cleanup Operations"));



    CloseHandle (g_ServiceStopEvent);



    g_ServiceStatus.dwControlsAccepted = 0;

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;

    g_ServiceStatus.dwWin32ExitCode = 0;

    g_ServiceStatus.dwCheckPoint = 3;



    if (SetServiceStatus (g_StatusHandle, &g_ServiceStatus) == FALSE)

    {

	    OutputDebugString(_T("My Sample Service: ServiceMain: SetServiceStatus returned error"));

    }

    

    EXIT:

    OutputDebugString(_T("My Sample Service: ServiceMain: Exit"));



    return;

}





VOID WINAPI ServiceCtrlHandler (DWORD CtrlCode)

{

    OutputDebugString(_T("My Sample Service: ServiceCtrlHandler: Entry"));



    switch (CtrlCode) 

	{

     case SERVICE_CONTROL_STOP :



        OutputDebugString(_T("My Sample Service: ServiceCtrlHandler: SERVICE_CONTROL_STOP Request"));



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

			OutputDebugString(_T("My Sample Service: ServiceCtrlHandler: SetServiceStatus returned error"));

		}



        // This will signal the worker thread to start shutting down

        SetEvent (g_ServiceStopEvent);



        break;



     default:

         break;

    }



    OutputDebugString(_T("My Sample Service: ServiceCtrlHandler: Exit"));

}





DWORD WINAPI ServiceWorkerThread (LPVOID lpParam)

{
	
	DWORD dwType = REG_SZ;
	HKEY hKey = 0;
	char value[1024];
	DWORD value_length = 1024;
	const char* subkey = "SOFTWARE\\Wow6432Node\\Immunity Inc\\El Jefe";
	RegOpenKey(HKEY_LOCAL_MACHINE,subkey,&hKey);
	RegQueryValueEx(hKey, "El Jefe", NULL, &dwType, (LPBYTE)&value, &value_length);
	LPCSTR strval = value;

	OutputDebugString(_T(strval));
    OutputDebugString(_T("My Sample Service: ServiceWorkerThread: Entry"));
	HANDLE ph;
	STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

	CreateProcess(strval, NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

	OutputDebugString(_T("Process should be made"));
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
    OutputDebugString(_T("My Sample Service: ServiceWorkerThread: Exit"));

	ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);

	TerminateProcess(ph,-1);

    return ERROR_SUCCESS;

}