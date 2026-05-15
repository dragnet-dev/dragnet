package kql

// tableMap maps Sigma logsource.category to the KQL table name in MDE/Sentinel.
var tableMap = map[string]string{
	"network_connection": "DeviceNetworkEvents",
	"file_event":         "DeviceFileEvents",
	"process_creation":   "DeviceProcessEvents",
	"process_access":     "DeviceEvents",
	"registry_event":     "DeviceRegistryEvents",
	"dns_query":          "DeviceNetworkEvents",
}

// fieldMap translates Sigma field names to KQL column names.
var fieldMap = map[string]string{
	// Network
	"DestinationHostname": "RemoteUrl",
	"DestinationIp":       "RemoteIP",
	"DestinationPort":     "RemotePort",
	"SourceIp":            "LocalIP",
	// Process
	"Image":             "FolderPath",
	"CommandLine":       "ProcessCommandLine",
	"ParentImage":       "InitiatingProcessFolderPath",
	"ParentCommandLine": "InitiatingProcessCommandLine",
	// File
	"TargetFilename": "FolderPath",
	"Hashes":         "SHA256",
	// Registry
	"TargetObject": "RegistryKey",
	// General
	"User": "AccountName",
}

// projectFields defines the columns to include in | project for each table.
var projectFields = map[string][]string{
	"DeviceNetworkEvents":  {"Timestamp", "DeviceName", "RemoteUrl", "RemoteIP", "RemotePort", "InitiatingProcessCommandLine"},
	"DeviceFileEvents":     {"Timestamp", "DeviceName", "FolderPath", "SHA256", "InitiatingProcessCommandLine"},
	"DeviceProcessEvents":  {"Timestamp", "DeviceName", "FolderPath", "ProcessCommandLine", "InitiatingProcessFolderPath", "InitiatingProcessCommandLine"},
	"DeviceEvents":         {"Timestamp", "DeviceName", "ActionType", "InitiatingProcessFolderPath", "InitiatingProcessCommandLine"},
	"DeviceRegistryEvents": {"Timestamp", "DeviceName", "RegistryKey", "RegistryValueName", "RegistryValueData"},
}
