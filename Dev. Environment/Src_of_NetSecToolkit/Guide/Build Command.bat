pyinstaller --onefile --noconsole --icon="Assets\NetSec_ICON.ico" --version-file="Assets\File_of_Version_Info.txt" `
  --add-data "PortScannerProgram.py;." `
  --add-data "AppConnectionControlProgram.py;." `
  --add-data "LiveNetworkMonitoringProgram.py;." `
  --add-data "PacketFilteringProgram.py;." `
  --add-data "ServicesDictionary.py;." `
  --add-data "Assets\NetSec_logo.png;Assets" `
  GUI.py