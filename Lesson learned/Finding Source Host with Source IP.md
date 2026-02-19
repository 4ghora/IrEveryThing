# Finding Source Host with Source IP

## Directly From Sentinel

```
SecurityEvent
| where IpAddress == "<Enter IP Here>"
| where eventID == "4624" or Activity == "4624 - An account was successfully logged on."
| where Account endswith "$"
| project Account, IpAddress, EventID, Activity, Computer
| summarize by Account, IpAddress, Activity, Computer
```
+ Host with $ sign parsed in Account section is your Host associated with IP.

## Using Defender table:
```
DeviceNetworkInfo
| where isnotempty(DeviceName)
| where IPAddresses containes "<Enter IP Here>"
| summarize by DeviceName, IPAddresses
```
+ Host in DeviceName is your device associated with IP.