unit RAEngine200;

interface

uses
    EasyPID, TlHelp32, Vcl.Buttons, Vcl.Forms, Messages, Vcl.Menus,
    System.SysUtils, Vcl.Controls, Windows, System.Classes, Vcl.StdCtrls;

function CheckTokenMembership( TokenHandle: THandle; SidToCheck: PSID;
var IsMember: Boolean ): Boolean; stdcall; external advapi32;

type
    TMain = class(TForm)
        function IsAdmin: Boolean;
        procedure Initialize( Sender: TObject );
        procedure DeleteHook( Sender: TObject );
    end;

    function GetImageBase: Cardinal;
    function WritableMemory( Code: Array of Byte ): Pointer;
    function HookProc( Code: Integer; wParam, lParam: NativeUInt ): Integer; stdcall;

var
    Main: TMain;

implementation

{$R *.dfm}
{$RANGECHECKS OFF}

type
    RExternalThread = record
        Thread: NativeUInt;
        Memory: Pointer;
    end;

    KBDLLHOOKSTRUCT = record
        vkCode: DWORD;
        scanCode: DWORD;
        flags: DWORD;
        time: DWORD;
        dwExtraInfo: Integer;
    end;
    PKBDLLHOOKSTRUCT = ^KBDLLHOOKSTRUCT;

var
    fPID: Cardinal;
    fHandle: NativeUInt;
    Found: Boolean;
    Hook: HHook;

    // Variables for "remote" code
    ExternalThread: RExternalThread;

const
    WinTitle = 'Red Alert';
    WinExename = 'RA95.EXE';

procedure Debug( Text: String; Args: Array of Const );
begin
    {$IFDEF DEBUG}
    AllocConsole;
    SetConsoleTitle( 'Debug' );
    Write( '"' + Format( Text, Args ) + '"'#10#13 );
    {$ENDIF}
end;

function WriteMemoryEx( Address: Cardinal; Value: Array of Byte ): Integer;
var
    I, Written: NativeUInt;
begin
    Result := 0;
    try
        if Length( Value ) <> 0 then
        begin
            for I := Low( Value ) to High( Value ) do
            begin
                WriteProcessMemory(
                    fHandle, Ptr( Address ), Addr( Value[I] ),
                    1, Written
                );

                Inc( Result, Written );
                Inc( Address );
            end;
        end;
    except
        Debug( 'Unknown exception at @WriteMemoryEx', [] );
    end;
end;

procedure RemoteThreadFunc;
begin
    try
        WaitForSingleObject( ExternalThread.Thread, INFINITE );
        VirtualFreeEx( fHandle, ExternalThread.Memory, 0, MEM_RELEASE );
    finally
        CloseHandle( ExternalThread.Thread );
    end;

    Debug( 'Remote thread has been executed', [] );
end;

function IsRemoteThreadActive: Boolean;
var
    Status: Cardinal;
begin
    Result := False;
    GetExitCodeThread( ExternalThread.Thread, Status );

    if Status = STILL_ACTIVE then Result := True;
end;

function TMain.IsAdmin: Boolean;
var
    AdminGroup: PSID;
const
    SECURITY_NT_AUTHORITY: TSIDIdentifierAuthority = (
        Value: ( 0, 0, 0, 0, 0, 5 )
    );
begin
    Result := AllocateAndInitializeSid(
        SECURITY_NT_AUTHORITY, 2, $20, $220, 0, 0, 0, 0, 0, 0, AdminGroup
    );

    if not CheckTokenMembership( 0, AdminGroup, Result ) then
        Result := False;

    FreeSid( AdminGroup );
end;

function DebugPrivilege: Boolean;
var
    hToken: NativeUInt;
    OutputLength: Cardinal;
    Privileges: TOKEN_PRIVILEGES;
const
    SE_DEBUG_NAME: PChar = 'SeDebugPrivilege';
begin
    Result := False;

    if OpenProcessToken( GetCurrentProcess, TOKEN_ALL_ACCESS, hToken ) then
    begin
        if LookupPrivilegeValue( nil, SE_DEBUG_NAME, Privileges.Privileges[0].Luid ) then
        begin
            Privileges.PrivilegeCount := 1;
            Privileges.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;

            if AdjustTokenPrivileges( hToken, False, Privileges,
            SizeOf( TOKEN_PRIVILEGES ), nil, OutputLength ) then
            begin
                if GetLastError = ERROR_SUCCESS then
                    Result := True;
            end;
        end;
    end;

    CloseHandle( hToken );
end;

function GetPID: Cardinal;
var
    I: Byte;
begin
    for I := 0 to 4 do
    begin
        case I of
            0: Result := GetPidFromFindWin( WinTitle, WinTitle );
            1: Result := GetPidFromWinTitle( WinTitle );
            2: Result := GetPidFromWinClass( WinTitle );
            else Result := GetPidFromExeName( WinExename );
        end;

        if Result <> 0 then Break;
    end;
end;

procedure ClearConsole;
var
    I: Integer;
    StdOut: HWND;
    Coord: TCoord;
    ScreenInfo: TConsoleScreenBufferInfo;
begin
    Coord.X := 0;
    Coord.Y := 0;

    StdOut := GetStdHandle( STD_OUTPUT_HANDLE );
    GetConsoleScreenBufferInfo( StdOut, ScreenInfo );

    for I := 1 to ScreenInfo.dwSize.Y do WriteLn( '' );

    SetConsoleCursorPosition( StdOut, Coord );
end;

procedure ThreadFunc;
var
    PID: Cardinal;
begin
    if DebugPrivilege then
        Debug( 'Debug privileges gained', [] );

    while True do
    begin
        fPID := 0;
        Debug( 'Process is not attached', [] );
        Found := False;

        while not Found do
        begin
            PID := GetPID;
            fHandle := OpenProcess( MAXIMUM_ALLOWED, False, PID );
            if ( fHandle <> 0 ) then
            begin
                fPID := PID;
                Found := True;
            end;
            Sleep( 1000 );
        end;

        PID := STILL_ACTIVE;
        Debug( 'Process (#%.4X) is attached', [fPID] );
        while PID = STILL_ACTIVE do
        begin
            Sleep( 2500 );
            GetExitCodeProcess( fHandle, PID );
        end;

        ClearConsole;
    end;
end;

function StartThread( Address: Pointer ): NativeUInt;
var
    pId: Cardinal;
begin
    Result := CreateThread( nil, 0, Address, nil, 0, pId );
end;

function ReadMemory( Address: Cardinal; Size: Byte = 4 ): Cardinal;
var
    Read, Buffer: NativeUInt;
begin
    Result := 0;

    if Found then
    begin
        if Size > 4 then Size := 4;

        ReadProcessMemory( fHandle, Ptr( Address ), Addr( Buffer ), Size, Read );
        Debug( 'Process memory (#%.6X), read %d bytes', [Address, Read] );

        Result := Buffer;
    end;
end;

function GetImageBase: Cardinal;
var
    Handle: Integer;
    Module: TModuleEntry32;
begin
    Result := 0;

    Handle := CreateToolhelp32Snapshot( TH32CS_SnapModule, fPID );
    if Handle <> -1 then
    begin
        try
            Module.dwSize := SizeOf( Module );
            if Module32First( Handle, Module ) then
                Result := Module.hModule;
        finally
            CloseHandle( Handle );
        end;
    end;
end;

function WritableMemory( Code: Array of Byte ): Pointer;
var
    Memory: Pointer;
    MemInfo: MEMORY_BASIC_INFORMATION;
begin
    Result := nil;

    while Found do
    begin
        Memory := VirtualAllocEx(
            fHandle, nil, Length( Code ), MEM_COMMIT, PAGE_EXECUTE_READWRITE
        );

        if Memory = nil then Continue;
        Debug( 'Allocate @VirtualAllocEx (#%.6X)', [Cardinal( Memory )] );

        VirtualQueryEx( fHandle, Memory, MemInfo, SizeOf( MemInfo ) );
        if ( MemInfo.BaseAddress = Memory ) and
           ( MemInfo.Protect = PAGE_EXECUTE_READWRITE ) then
        begin
            if WriteMemoryEx( Cardinal( Memory ), Code ) = Length( Code ) then
            begin
                Debug( 'Passed @WritableMemory', [] );
                Result := Memory;

                Break;
            end;
        end;

        Debug( 'Free @VirtualFreeEx: (#%.6X)', [Cardinal( Memory )] );
        VirtualFreeEx( fHandle, Memory, 0, MEM_RELEASE );
    end;
end;

function RemoteThread( Code: Array of Byte; Value: Cardinal = 0 ): Cardinal;
var
    ThreadId: Cardinal;
begin
    Result := 0;
    if IsRemoteThreadActive then Exit;
    //{$DEFINE THREAD_DEBUG}
    if Found then
    begin
        ExternalThread.Memory := WritableMemory( Code );
        if ExternalThread.Memory = nil then Exit;

        ExternalThread.Thread := CreateRemoteThread( fHandle, nil, 0,
        ExternalThread.Memory, Pointer( Value ), CREATE_SUSPENDED, ThreadID );
        if ExternalThread.Thread <> 0 then
        begin
            Result := ExternalThread.Thread;
            ResumeThread( ExternalThread.Thread );
            Debug( 'Remote thread (#%.4X) is initialized', [ThreadID] );

            {$IFNDEF THREAD_DEBUG}
            StartThread( @RemoteThreadFunc );
            {$ENDIF}
        end;
    end;
end;

procedure WriteMemory( Address, Value: Cardinal; Size: Byte = 4 );
var
    Used: NativeUInt;
begin
    try
        case Size of
            4: WriteProcessMemory( fHandle, Ptr( Address ), Addr( Value ), 4, Used );
            2: WriteProcessMemory( fHandle, Ptr( Address ), Addr( Value ), 2, Used );
            else WriteProcessMemory( fHandle, Ptr( Address ), Addr( Value ), 1, Used );
        end;
    except
        Debug( 'Unknown exception at @WriteMemory', [] );
    end;
end;

procedure Call( Key: Cardinal );

    function ReloadSpecialWeapon( Value: Byte ): Boolean;
    const
        MaxValue: Array[0..7] of Byte = (
            14, 15, 14, 14, 14, 14, 14, 14
        );
    var
        Buffer: Cardinal;
    begin
        Result := True;
        Buffer := ReadMemory( $669958 ) + ( $19 * Value + $4B );

        if ( Value = 7 ) and ( ReadMemory( Buffer ) <= 1 ) then
        begin
            Result := False;
            Exit;
        end;

        WriteMemory( Buffer, MaxValue[Value] );
    end;

var
    Buffer: Cardinal;
    Locked: Boolean;
begin
    Buffer := fPID;
    Locked := False;

    {$IFNDEF DEBUG}
    GetWindowThreadProcessId( GetForegroundWindow, Buffer );
    {$ENDIF}

    if ( not Found ) or ( fPID <> Buffer ) then Exit;

    case Key of
        $2070:
        begin
            // Disable in MP
            Locked := True;
            // Add money +$50000 (F1)
            Buffer := ReadMemory( $669958 ) + $197;

            if ReadMemory( Buffer ) >= 100000000 then
            begin
                WriteMemory( Buffer, 100000000 );
                Exit;
            end;

            WriteMemory( Buffer, ReadMemory( Buffer ) + 50000 );
            WriteMemory( Buffer + 4, 100000000 );

            WriteMemory( $66984E, ReadMemory( Buffer ) - 100 );
        end;
        $2071:
        begin
            // Disable in MP
            Locked := True;
            // Unlimited power (F2)
            Buffer := ReadMemory( $669958 ) + $1E3;

            WriteMemory( Buffer, 100000000 );
            WriteMemory( Buffer + 4, 0 );
        end;
        $2072:
        begin
            // Disable in MP
            Locked := True;
            // Instant build (F3)
            // Modifies game code (Needs rewrite!)
            // Warning! Works with AI too
            if ReadMemory( $4BED5C ) = 1166884491 then
                WriteMemory( $4BED5C, 2198689419 )
            else
                WriteMemory( $4BED5C, 1166884491 );
            if ReadMemory( $4BED60 ) = 1451968480 then
                WriteMemory( $4BED60, 57882174 )
            else
                WriteMemory( $4BED60, 1451968480 );
            if ReadMemory( $4BED64 ) = 3896412429 then
                WriteMemory( $4BED64, 3895854790 )
            else
                WriteMemory( $4BED64, 3896412429 );
        end;
        $2073:
        begin
            // Disable in MP
            Locked := True;
            // Build out of range (F4)
            // Modifies game code (Needs rewrite!)
            // Warning! Works with AI too
            if ReadMemory( $4AF835 ) = $01BF0A74 then
                WriteMemory( $4AF835, $01BFFF31 )
            else
                WriteMemory( $4AF835, $01BF0A74 );
        end;
        $2074:
        begin
            // Disable in MP
            Locked := True;
            // Reveal map (SHIFT+F5)
            // Call RA internal function
            // RA.DisableShroud()
            RemoteThread(
                [$B9, $AC, $FE, $52, $00, $31, $FF, $EB, $0E, $8B,
                 $1D, $58, $99, $66, $00, $B8, $50, $82, $66, $00,
                 $FF, $D1, $47, $0F, $BF, $D7, $81 ,$FA, $00, $40,
                 $00, $00, $7C, $E7, $C3]
            );
        end;
        $2075:
        begin
            // Disable in MP
            Locked := True;
            // Heal your units/structures (SHIFT+F6)
            // Call RA Internal function
            // RA.GetUnitMaxHealth()
            RemoteThread(
                [$31, $FF, $8B, $1D, $58, $99, $66, $00, $8B, $5B,
                 $01, $8B, $15, $30, $82, $66, $00, $8B, $14, $BA,
                 $85, $D2, $74, $1F, $38, $9A, $93, $00, $00, $00,
                 $75, $17, $8B, $C2, $8B, $4A, $11, $FF, $51, $34,
                 $85, $C0, $74, $0B, $66, $8B, $80, $2A, $01, $00,
                 $00, $66, $89, $42, $25, $47, $8B, $0D, $40, $82,
                 $66, $00, $39, $CF, $7E, $C9, $C3]
            );
        end;
        $2076:
        begin
            // Disable in MP
            Locked := True;
            // Spawn MCV to cursor location (SHIFT+F7)
            // Call RA internal function
            // RA.CreateMCV2CursorPosition()
            RemoteThread(
                [$8B, $35, $F0, $D9, $65, $00, $B8, $0B, $00, $00,
                 $00, $BB, $24, $8C, $57, $00, $FF, $D3, $8B, $F8,
                 $85, $FF, $74, $55, $80, $3D, $5C, $67, $66, $00,
                 $FF, $75, $4C, $8B, $DF, $8B, $4F, $21, $A1, $F0,
                 $17, $60, $00, $8B, $15, $58, $99, $66, $00, $8B,
                 $52, $01, $0F, $AF, $50, $04, $8B, $40, $10, $01,
                 $C2, $8B, $C3, $FF, $51, $20, $8B, $C8, $85, $C0,
                 $74, $25, $8B, $78, $11, $8B, $15, $6C, $82, $66,
                 $00, $A1, $A2, $8E, $66, $00, $6B, $C0, $3A, $01,
                 $C2, $8B, $C2, $31, $DB, $BA, $E0, $FD, $49, $00,
                 $FF, $D2, $8B, $D0, $8B, $C1, $FF, $57, $64, $C3]
            );
        end;
        $2077:
        begin
            // Disable in MP
            Locked := True;
            // Unlock all buildables (SHIFT+F8)
            // Call RA internal function
            // RA.EnableBuildables()
            RemoteThread(
                 [$83, $C2, $06, $52, $EB, $20, $14, $19, $1A, $1E,
                  $26, $28, $29, $FF, $09, $0B, $0C, $0D, $0E, $0F,
                  $10, $11, $12, $13, $14, $15, $16, $17, $FF, $0E,
                  $0F, $10, $FF, $01, $02, $03, $04, $FF, $8B, $35,
                  $58, $99, $66, $00, $BF, $1C, $D6, $54, $00, $31,
                  $C9, $51, $80, $BE, $32, $03, $00, $00, $01, $7C,
                  $3E, $31, $DB, $C6, $45, $F0, $06, $53, $8B, $55,
                  $F0, $B8, $50, $82, $66, $00, $FF, $D7, $8B, $45,
                  $F0, $8B, $55, $EC, $BB, $F0, $9C, $4A, $00, $FF,
                  $D3, $83, $F8, $00, $74, $07, $C6, $80, $62, $01,
                  $00, $00, $FF, $5B, $43, $8B, $45, $F4, $8A, $04,
                  $08, $38, $C3, $75, $03, $41, $EB, $F2, $83, $FB,
                  $2B, $7C, $C8, $80, $BE, $5A, $03, $00, $00, $01,
                  $7C, $40, $31, $DB, $C6, $45, $F0, $0E, $B1, $08,
                  $53, $8B, $55, $F0, $B8, $50, $82, $66, $00, $FF,
                  $D7, $8B, $45, $F0, $8B, $55, $EC, $BB, $F0, $9C,
                  $4A, $00, $FF, $D3, $83, $F8, $00, $74, $07, $C6,
                  $80, $62, $01, $00, $00, $FF, $5B, $43, $8B, $45,
                  $F4, $8A, $04, $08, $38, $C3, $75, $03, $41, $EB,
                  $F2, $83, $FB, $1A, $7C, $C8, $80, $BE, $0E, $03,
                  $00, $00, $01, $7C, $40, $31, $DB, $C6, $45, $F0,
                  $1D, $B1, $17, $53, $8B, $55, $F0, $B8, $50, $82,
                  $66, $00, $FF, $D7, $8B, $45, $F0, $8B, $55, $EC,
                  $BB, $F0, $9C, $4A, $00, $FF, $D3, $83, $F8, $00,
                  $74, $07, $C6, $80, $62, $01, $00, $00, $FF, $5B,
                  $43, $8B, $45, $F4, $8A, $04, $08, $38, $C3, $75,
                  $03, $41, $EB, $F2, $83, $FB, $16, $7C, $C8, $80,
                  $BE, $3E, $03, $00, $00, $01, $7C, $4E, $31, $DB,
                  $C6, $45, $F0, $02, $B1, $1B, $53, $8B, $55, $F0,
                  $B8, $50, $82, $66, $00, $FF, $D7, $8B, $45, $F0,
                  $8B, $55, $EC, $BB, $F0, $9C, $4A, $00, $FF, $D3,
                  $83, $F8, $00, $74, $07, $C6, $80, $62, $01, $00,
                  $00, $FF, $5B, $43, $8B, $45, $F4, $8A, $04, $08,
                  $38, $C3, $75, $11, $41, $80, $BE, $46, $03, $00,
                  $00, $01, $7C, $07, $80, $FB, $02, $77, $C1, $EB,
                  $E4, $83, $FB, $07, $7C, $BA, $80, $BE, $76, $03,
                  $00, $00, $01, $7C, $31, $31, $DB, $C6, $45, $F0,
                  $1F, $53, $8B, $55, $F0, $B8, $50, $82, $66, $00,
                  $FF, $D7, $8B, $45, $F0, $8B, $55, $EC, $BB, $F0,
                  $9C, $4A, $00, $FF, $D3, $83, $F8, $00, $74, $07,
                  $C6, $80, $62, $01, $00, $00, $FF, $5B, $43, $83,
                  $FB, $07, $7C, $D5, $58, $5A, $C3]
            );
        end;
        $2031..$2038:
        begin
            // Disable in MP
            Locked := True;
            // Warheads (NUM 1-8)
            Dec( Key, $2031 );
            if ReloadSpecialWeapon( Key ) then
            begin
                // Replace cursor with correct icon
                WriteMemory( $668EC6, Key * $100, 2 );
                // Call RA internal function
                // RA.AddSlot( ItemID, TypeID, @MenuID: INT )
                RemoteThread(
                    [$BB, Byte( Key ), 0, 0, 0, $BA, $13, 0, 0, 0, $B8, $50,
                    $82, $66, 0, $BF, $1C, $D6, $54, 0, $FF, $D7, $C3]
                );
            end
            else
                Call( $2074 );
        end;
    end;

    if Locked then
    begin
        //WriteMemory( $55555, 0 );
    end;
end;

function HookProc( Code: Integer; wParam, lParam: NativeUInt ): Integer;

    function GetModifiers: Word;
    const
        KEY_SHIFT = $1000;
        KEY_CONTROL = $2000;
        KEY_ALT = $4000;
    begin
        Result := 0;

        if ( GetAsyncKeyState( VK_CONTROL ) shr 31 ) = 1 then
            Inc( Result, KEY_CONTROL );
        if ( GetAsyncKeyState( VK_MENU ) shr 31 ) = 1 then
            Inc( Result, KEY_ALT );
        if ( GetAsyncKeyState( VK_SHIFT ) shr 31 ) = 1 then
            Inc( Result, KEY_SHIFT );
    end;

begin
    Result := 0;

    if wParam = WM_KEYDOWN then
        Call( PKBDLLHOOKSTRUCT( lParam ).vkCode + GetModifiers );

    if Code < 0 then Result := CallNextHookEx( Hook, Code, wParam, lParam );
end;

procedure TMain.Initialize( Sender: TObject );
begin
    Application.Title := Caption;
    Debug( '%s is running', [Caption] );

    if IsAdmin then Debug( 'Admin-level privileges acquired', [] );

    if StartThread( @ThreadFunc ) = 0 then
        Debug( 'Thread initialization failed (#%.4X)', [GetLastError] );

    Hook := SetWindowsHookEx( WH_KEYBOARD_LL, @HookProc, hInstance, 0 );
    if Hook = 0 then Debug( 'Keyboard hooking failed (#%.4X)', [GetLastError] );
end;

procedure TMain.DeleteHook( Sender: TObject );
begin
    UnhookWindowsHookEx( Hook );
end;

end.
