# Install VMware before building the lab

Setup checks for VMware before downloading lab images. Windows checks `vmrun.exe`
on PATH and Workstation's installation registry entries; Linux checks `vmrun`
on PATH. If it cannot find VMware, setup stops and prints the steps below.
A detected executable confirms installation discovery, not working virtualization.

1. Open [Broadcom Support](https://support.broadcom.com/) and sign in or create a
   basic account. Workstation Pro is available free for personal, educational and
   commercial use. Downloads still require a Broadcom account.
2. Find **Free Software Downloads** and select **VMware Workstation Pro**.
   Choose the installer for your host: **Windows x64** or **Linux x86-64**.
   Follow [Broadcom's illustrated download instructions](https://knowledge.broadcom.com/external/article/368734/download-desktop-hypervisor-workstation.html)
   for current portal navigation and any profile/terms prompts.
3. On Windows, run the downloaded installer as administrator. On Linux, run the
   downloaded `.bundle` installer using the vendor instructions and complete any
   kernel-module build/signing requirements for your distribution.
4. Launch Workstation and complete its first-run prompts. Reboot if the installer
   requests it. Confirm hardware virtualization is enabled and Workstation can
   start a compatible guest.
5. Return to this repository in a new terminal. Run `./setup.sh` on Linux or
   `.\setup.ps1` in an elevated PowerShell on Windows. Setup checks again before
   proceeding. You do not need to clone the repository again.

If Workstation is already installed but setup cannot find it, locate `vmrun`
(or `vmrun.exe`) in the Workstation installation directory and add that directory
to the current terminal's PATH, or repair the installation. Windows setup normally
finds installations through the registry even when PATH is missing.

This workshop build targets Workstation on x86-64 hosts. Fusion on macOS and ARM
hosts are not validated. Use the assigned conference lab if your machine cannot
run the supported configuration. Docker Desktop is not required.

Official licensing reference:
https://knowledge.broadcom.com/external/article/368667/download-and-license-information-for-vmw.html
