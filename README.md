# ESFriend
## A minimal malware analysis sandbox framework for macOS

Introducing ESFriend. A coordinated set of python wrappers for powerful applications on macOS, coming together to form a malware analysis sandbox. These application wrappers cooperate with each other using MongoDB to pass control to the next step.


## Free applications:
ESF Playground - https://themittenmac.com/the-esf-playground/

mitmproxy - https://mitmproxy.org/

ssdeep - https://ssdeep-project.github.io/ssdeep/index.html

p7zip - http://p7zip.sourceforge.net/


## Paid applications:
Faronics Deep Freeze (69.30 USD) - https://www.faronics.com/products/deep-freeze/mac

ESFriend is designed to use a physical macOS machine as the sandbox environment, then perform cleanup by using Faronics Deep Freeze.


## Analysis machine set up
This setup assumes you will use a Mac for the analysis machine. Windows and Linux should just work fine, configuration instructions are not yet included.


### Install homebrew:
We all know the command:

`/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`


### Install python:
I'm using python3.9.13

Link to installer page:
https://www.python.org/downloads/release/python-3913/


### Install mitmproxy and ssdeep
`brew install mongodb-community mitmproxy ssdeep`

Follow the instructions from brew to configure mongodb to automatically start on reboot

**Important Note: The analysis process for ESFriend uses a mitmproxy script to extract headers. Installing the python package for mitmproxy so that you can write additional scripts will replace the up to date mitmproxy on $PATH with an older version that will crash if used to capture packets from the sandbox machine.**


### Install necessary python modules:
Installing these to the system because I have not investigated environment variables with subprocess.

`sudo -H python3.9 -m pip install pymongo ssdeep Flask Flask-Table`

**Important Note: You can install Flask and Flask-Table to a virtualenv to keep those modules off of the system python3.9 environment. The modules `pymongo` and `ssdeep` are used in subprocesses and necessary on the system at this time. Additionally, `ssdeep` is only used for greating goodlist entries, not comparing at this time.**


## Sandbox machine set up
Analysis machine can be any physical macOS machine, Intel or Apple silcon.


### Install homebrew:
Again:

`/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`


### Install p7zip

`brew install p7zip`


### Install python:
Again - link to installer page:
https://www.python.org/downloads/release/python-3913/


### Install necessary python modules:

`sudo -H python3.9 -m pip install pymongo`

THe only module needed on the analysis machine at this time is pymongo.


### Install ESF Playground:
https://themittenmac.com/the-esf-playground/

Configure the SystemExtension so ESF Playground can be run without root.

User Security & Privacy menu to add `Terminal.app` to Full Disk Access


### Script configuration:
`ESFriend/config.py` and `agent/agent_config.py` need to be modified so they contain the correct path for corresponding applications, correct database connection string, and machine configuration.

Modify the shebangs in each file so they point to your python3.9 system installation for both Analysis (ESFriend directory) and Sandbox (agent directory) scripts.

Ensure execution flags are set for scripts that are called through subprocess or cron.


### Configure cron for Full Disk Access:
Use Security & Privacy menu to add `/usr/sbin/cron` to Full Disk Access

Configure crontab to run the agent.py script on reboot

`crontab -e`

`@reboot cd /path/to/agent/ && ./agent.py`


### Configure sudoers file to allow reboot without password:
`sudo nano /etc/sudoers`

Add the following line to the bottom of the file, replacing `username` with your own user account
`username ALL=NOPASSWD:/sbin/reboot`


### Install Faronics Deep Freeze for Mac:
https://www.faronics.com/products/deep-freeze/mac

30 day trial is available

Switch the system to a frozen state

**Important Note: Invalid key from payment processor. After purchasing the software you may need to contact support immediately because the license provided from the payment processer is not valid. Contacting support through the payment processor has been successful for me in the past.**


## Using ESFriend
After the agent is configured and running you can start the Analysis machine process

`./esfriend.py`

To clean the database (including the goodlist) and start over use

`./esfriend.py --cleangoods`

To clean only the job, machine, and run databases use:

`./esfriend.py --clean`


### File submission:
`./submit.py sample_path timeout tags`

Example:

`./submit.py ~/SamplePath.o 60 cve-2022-0000`

You must include a timeout (in seconds) and tags (delimited however you like), there are no default values.

### ESFriend Web
Results can be viewed using the ESFriend web.py script

From the ESFriend folder type:

`export FLASK_APP=web`

`flask run`

By default you should be able to navigate to:
http://localhost:5000


### Goodlist
`goodlist.py` can be used to generate a list of good event strings that should be ignored from a previous run. Upon execution it will prompt you with a list of runs and ask you to select which to generate good event strings from.