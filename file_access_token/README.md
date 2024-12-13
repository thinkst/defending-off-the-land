### Windows ProjFS Examples.


https://learn.microsoft.com/en-us/windows/win32/projfs/projected-file-system

SMB example show cases how to use ProjFS to alert on share access from a remote system

Tarpit example shows how to create an approved Process list, and take actions, return random errors, delay loading of files etc...

Sample Invocation - Ensure `$(Get-Content .\csharp\test_file.csv -Raw)` is passed to parse the csv file.

```
Sample Invocation.
.\CanaryFS.ps1 -TaskName "CanaryFS" -TaskDescription "Create Fake Files" -ScriptPath "C:\users\Thinkst\data-script.ps1" -RootPath "C:\CanaryFs"

Sample exe invocation
.\CanaryFS.exe C:\vfstest $(Get-Content .\csharp\test_file.csv -Raw) example.canarytokens.com true

```

