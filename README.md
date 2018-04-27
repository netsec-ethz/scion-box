# Setup
The vision for SCION boxes is that they could either run as dedicated ASes or as SCIONLab ASes to which the other ASes could connect to with minimal setup required from the end user.
Boxes are remotely administrated and the user can interact with the box via the SCION coordination service.

## Install an Attachment Point
To setup an Attachment Point (AP) we will need several files:
- VPN related credential files. These files are usually generated where the Coordinator runs. Please check the instructions in the *README* of the *scion-coord* project.
  - ca.crt
  - dh4096.pem
  - my_AS.crt
  - my_AS.key
- `update_gen.py` and `updateGen.sh` scripts. These allow the installed AS (that has an AP) to update itself, e.g. when another AS has been attached to this one.
- `install_attachment_point.sh` script. Just convenient to setup the VPN for the AP. In the future this script may do more, like checking some ports are not blocked by a firewall, etc.
The script called `install_attachment_point.sh` needs at least the four VPN credential files for a given AP. It is invoked specifying the name of the AS.
For the infrastructure APs it is convenient to copy all the credential files together with the installation script on each AP we want to install, run the script, and then delete the all these credentials and the script.
```
/tmp $ ls install_aps/
AS1-7.crt  AS1-7.key  AS5-51.crt  AS5-51.key  AS6-62.crt  AS6-62.key  ca.crt  dh4096.pem  install_attachment_point.sh

/tmp $ cd install_aps/
juan@juan /tmp/install_aps $

/tmp/install_aps $ ./install_attachment_point.sh -n AS6-62
[sudo] password for theuser:
Done.

/tmp/install_aps $ cd ..
/tmp $ rm -r install_aps
```
This way the process is almost completely automated, with the exception that something has to check that the AP is reached using an appropriate VPN connection.
