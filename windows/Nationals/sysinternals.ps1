[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ProgressPreference = 'SilentlyContinue'

netsh a f a r n=WEB_OUT dir=out a=allow prot=TCP remoteport="80,443"

iwr "https://download.sysinternals.com/files/SysinternalsSuite.zip" -o "C:\Users\Administrator\Documents\Sysinternals.zip" -UseBasicParsing

netsh a f del r n=WEB_OUT
