unit EasyPID;

interface

uses
    Windows, TlHelp32, SysUtils, PsApi;

function GetPidFromWinTitle( Title: String ): Cardinal;
function GetPidFromWinClass( Classname: String ): Cardinal;
function GetPidFromFindWin( Classname, Title: String ): Cardinal;
function GetPidFromExeName( ExeName: String ): Cardinal;
function GetPIDPath( PID: Cardinal ): String;
function GetHandlePath( pHandle: Cardinal ): String;

implementation

function GetPIDPath( PID: Cardinal ): String;
var
    Handle: Cardinal;
    Module: TModuleEntry32;
begin
    Result := '';
    Handle := CreateToolhelp32Snapshot( TH32CS_SnapModule, PID );
    if Handle <> -1 then
    begin
        try
            Module.dwSize := SizeOf( Module );
            if Module32First( Handle, Module ) then
                Result := String( Module.szExePath );
        finally
            CloseHandle( Handle );
        end;
    end;
end;

function GetHandlePath( pHandle: Cardinal ): String;
var
    Buffer: PChar;
    OK: Cardinal;
begin
    Result := '';
    OK := GetModuleFileNameEx( pHandle, 0, Buffer, 1024 );
    if OK <> 0 then
        Result := Buffer;
end;

function GetPidFromWinTitle( Title: String ): Cardinal;
var
    Handle: HWND;
begin
    Result := 0;
    Handle := FindWindow( nil, PChar( Title ) );
    if Handle <> 0 then
        GetWindowThreadProcessId( Handle, Result );
end;

function GetPidFromWinClass( Classname: String ): Cardinal;
var
    Handle: HWND;
begin
    Result := 0;
    Handle := FindWindow( PChar( Classname ), nil );
    if Handle <> 0 then
        GetWindowThreadProcessId( Handle, Result );
end;

function GetPidFromFindWin( Classname, Title: String ): Cardinal;
var
    Handle: HWND;
begin
    Result := 0;
    Handle := FindWindow( PChar( Classname ), PChar( Title ) );
    if Handle <> 0 then
        GetWindowThreadProcessId( Handle, Result );
end;

function GetPidFromExeName( ExeName: String ): Cardinal;
var
    OK: Boolean;
    Handle: Cardinal;
    mEntry: TProcessEntry32;
begin
    Result := 0;
    Handle := CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    OK := Process32First( Handle, mEntry );
    while OK <> False do
    begin
        if ExeName = ExtractFileName( mEntry.szExeFile ) then
        begin
            Result := mEntry.th32ProcessID;
            Break;
        end;
        OK := Process32Next( Handle, mEntry );
    end;
end;

end.
 