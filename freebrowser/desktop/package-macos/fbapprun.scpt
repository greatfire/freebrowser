set scriptPath to path to me as text
set posixScriptPath to POSIX path of scriptPath
set scriptDir to do shell script "dirname " & quoted form of posixScriptPath
set binaryPath to scriptDir & "/freebrowser_mac"
tell application "Terminal"
  do script (quoted form of binaryPath & "; exit")
  activate
end tell
return ""