# esfriend
## A minimal malware analysis sandbox for macOS

Introducing esfriend. A coordinated set of python wrappers for powerful applications on macOS, coming together to form a malware analysis sandbox. These application wrappers cooperate with each other using MongoDB to pass control to the next step.

## October 17 2022 Update:

**I didn't realize the snapshot restoration feature through the macOS repair menu could serve as a free (but slower) replacement for Deep Freeze, so technically this whole sandbox is free (minus hardware cost)!**

**I've added the option to use eslogger output instead of ESF Playground on macOS Ventura (where eslogger is available). I'm still working on parsing the output and gathering additional data. This at least gives me the ability to investigate the more complex output of eslogger in comparison to ESF Playground.**

## December 19 2022 Update:

**esfriend no longer uses ESF Playground to record events, this means that macOS Ventura is required because we're using eslogger exclusively**

**I had to split "close" events and "exec" events into their own eslogger wrapper scripts. Allowing a single eslogger process to monitor for a single event type ensures that we collect as many events as accurately as possible.**

**I have also modified the css for the results website, as well as added more navigation options to help quickly analyze the output from eslogger and system log.**

**pictures coming soon**

**I've also been using Faronics Deep Freeze with SIP disabled and it seems to be working fine. This configuration allows easier execution of most malware that is packaged correctly.**

## Free applications:

ESF Playground - https://themittenmac.com/the-esf-playground/ - leaving this here because it helped get the ball rolling a lot

mitmproxy - https://mitmproxy.org/

ssdeep - https://ssdeep-project.github.io/ssdeep/index.html

p7zip - http://p7zip.sourceforge.net/

eslogger - Announced in this video https://developer.apple.com/videos/play/wwdc2022/110345/


## Paid applications:
Faronics Deep Freeze (69.30 USD) - https://www.faronics.com/products/deep-freeze/mac

esfriend is designed to use a physical macOS machine as the sandbox environment, then perform cleanup by using Faronics Deep Freeze.


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

**Important Note: The analysis process for esfriend uses a mitmproxy script to extract headers. Installing the python package for mitmproxy so that you can write additional scripts will replace the up to date mitmproxy on $PATH with an older version that will crash if used to capture packets from the sandbox machine.**


### Install necessary python modules:
Installing these to the system because I have not investigated environment variables with subprocess.

`sudo -H python3.9 -m pip install pymongo ssdeep Flask Flask-Table`

**Important Note: You can install Flask and Flask-Table to a virtualenv to keep those modules off of the system python3.9 environment. The modules `pymongo` and `ssdeep` are used in subprocesses and necessary on the system at this time. Additionally, `ssdeep` is only used for greating goodlist entries, not comparing at this time.**


## Sandbox machine set up
Analysis machine can be any physical macOS machine, Intel or Apple silcon.


### Install Rosetta (on Apple Silicon machines):
You'll need any x86 application to show the prompt to install Rosetta. Even running a simple hello world program will start the process.

Let me know if you need help generating an x86 MachO.


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


### Script configuration:
`esfriend/config.py` and `agent/agent_config.py` need to be modified so they contain the correct path for corresponding applications, correct database connection string, and machine configuration.

Modify the shebangs in each file so they point to your python3.9 system installation for both Analysis (esfriend directory) and Sandbox (agent directory) scripts.

Ensure execution flags are set for scripts that are called through subprocess or cron.


### Configure cron for Full Disk Access:
Use Security & Privacy menu to add `/usr/sbin/cron` to Full Disk Access

Configure crontab to run the agent.py script on reboot

`crontab -e`

`@reboot cd /path/to/agent/ && /usr/bin/sudo ./agent.py`

### Configure sudoers file to allow reboot, eslogger, and the agent python without password:
`sudo nano /etc/sudoers`

Add the following line to the bottom of the file, replacing `username` with your own user account

`username ALL=NOPASSWD:/sbin/reboot, /usr/bin/eslogger, /Users/username/Desktop/agent/agent.py`

Make sure to replace the path to agent.py with the path on your system

### Install Faronics Deep Freeze for Mac:

**Deep Freeze is not required to have a functional sandbox. You can create a snapshot using `tmutil snapshot` then restore the clean state using the macOS Repair menu. Deep Freeze does expedite the cleanup process by a considerable amount of time.**

https://www.faronics.com/products/deep-freeze/mac

30 day trial is available

Switch the system to a frozen state

**Important Note: Invalid key from payment processor. After purchasing the software you may need to contact support immediately because the license provided from the payment processer is not valid. Contacting support through the payment processor has been successful for me in the past.**


## Using esfriend
After the agent is configured and running you can start the Analysis machine process

`./esfriend.py`

To clean the database (including the goodlist) and start over use

`./esfriend.py --cleangoods`

To clean only the job, machine, and run databases use:

`./esfriend.py --clean`


### File submission:
`./submit.py sample_path timeout tags`

Example:

`./submit.py ~/SamplePath.o 60 cve-2022-0000,macho`

You must include a timeout (in seconds) and tags (delimited however you like), there are no default values.

### esfriend Web
Results can be viewed using the esfriend web.py script

From the esfriend folder type:

`export FLASK_APP=web`

`flask run`

By default you should be able to navigate to:
http://localhost:5000


### Goodlist
`goodlist.py` can be used to generate a list of good event strings that should be ignored from a previous run. Upon execution it will prompt you with a list of runs and ask you to select which to generate good event strings from.