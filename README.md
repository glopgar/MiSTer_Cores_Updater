# MiSTer_Cores_Updater
Script for updating MiSTer cores from any repository

Script for downloading cores for the MisTer FPGA.
This is a preview release, enabled for downloading cores from these repositories:
* Jotego arcade cores. Beta cores are downloaded to a separate folder, including alternative MRAs.
* Kyp069 alternative ZX Spectrum 48K 

Instructions:

Upload the script and config files to the MiSTer `/Scripts` folder (by default `/media/fat/Scripts`:
* update_cores.py
* update_cores.ini

You can change the cores destination paths from the `update_cores.ini`.

Execute the script: `update_cores.py`
