Set-NetFirewallProfile -Profile Domain -LogAllowed True -LogBlocked True
Set-NetFirewallProfile -Profile Private -LogAllowed True -LogBlocked True
Set-NetFirewallProfile -Profile Public -LogAllowed True -LogBlocked True

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$ProgressPreference = 'SilentlyContinue'
iwr "https://download.splunk.com/products/universalforwarder/releases/9.2.5/windows/splunkforwarder-9.2.5-7bfc9a4ed6ba-x64-release.msi" -O "C:\Users\Administrator\Documents\splunkforwarder.msi" -UseBasicParsing

$receiving_indexer = "192.168.220.95:9997"
$firewall_log = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"

msiexec.exe /i C:\Users\Administrator\Documents\splunkforwarder.msi AGREETOLICENSE=Yes SPLUNKUSERNAME=Administrator SPLUNKPASSWORD=password MONITOR_PATH="$firewall_log" RECEIVING_INDEXER=$receiving_indexer WINEVENTLOG_APP_ENABLE=1 WINEVENTLOG_SEC_ENABLE=1 WINEVENTLOG_SYS_ENABLE=1 WINEVENTLOG_SET_ENABLE=1 /quiet
