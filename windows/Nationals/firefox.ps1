[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ProgressPreference = 'SilentlyContinue'

netsh a f a r n=WEB_OUT dir=out a=allow prot=TCP remoteport="80,443"

iwr "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US&attribution_code=c291cmNlPXd3dy5nb29nbGUuY29tJm1lZGl1bT1yZWZlcnJhbCZjYW1wYWlnbj0obm90IHNldCkmY29udGVudD0obm90IHNldCkmZXhwZXJpbWVudD0obm90IHNldCkmdmFyaWF0aW9uPShub3Qgc2V0KSZ1YT1jaHJvbWUmY2xpZW50X2lkX2dhND0obm90IHNldCkmc2Vzc2lvbl9pZD0obm90IHNldCkmZGxzb3VyY2U9bW96b3Jn&attribution_sig=8736a93bec69fc1c243683f991d9ab1e2e55c29d874ba87a68392df75ba4733f" -o "C:\Users\Administrator\Documents\Firefox.exe" -UseBasicParsing

netsh a f del r n=WEB_OUT
