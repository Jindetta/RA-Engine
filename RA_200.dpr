program RA_200;

uses
    Vcl.Forms, Vcl.Themes, Vcl.Styles, Windows, Dialogs, Classes,
    SysUtils, RAEngine200;

{$R *.res}

const
    ADMIN_TITLE: PChar = 'Insufficient privileges';
    ADMIN_TEXT: PChar = 'Application might need admininistor ' +
    'privileges to run properly.'#13'Do you want to continue anyway?';

begin
    Application.Initialize;
    Application.MainFormOnTaskbar := True;
    TStyleManager.TrySetStyle( 'Obsidian' );
    Application.CreateForm( TMain, Main );

    {$IFNDEF DEBUG}
    if not Main.IsAdmin then
    if Application.MessageBox( ADMIN_TEXT, ADMIN_TITLE, 52 ) = 7 then Exit;
    {$ENDIF}

    Application.Run;
end.
