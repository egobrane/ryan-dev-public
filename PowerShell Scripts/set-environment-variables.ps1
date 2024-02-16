# This script "Elegantly" sets machine environment variables for all users on a Windows system
# First param is variable name, second is value, third is target
[Environment]::SetEnvironmentVariable("AZCOPY_AUTO_LOGIN_TYPE", "MSI", "Machine")
[Environment]::SetEnvironmentVariable("AZCOPY_DISABLE_SYSLOG", "true", "Machine")