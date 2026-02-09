#!/usr/bin/env bash

# Setting up for AlmaLinux

# OpenSSL development package (General Prerequisites)
sudo yum install -y openssl-devel

# Lex and Yacc (Spines Prerequisites)
sudo yum install -y flex byacc

# QT dev. package and webkit (HMI Prerequisite) (NOTE: i think instead of qt5-devel we need qt5-qtbase-devel now https://lists.fedoraproject.org/archives/list/devel@lists.fedoraproject.org/thread/WO625MVYEAAJNHNRLEEJDVZTIWMQOBRR/)
# sudo yum install -y qt5-devel
sudo yum install -y qt5-qtbase-devel
sudo yum install -y qt5-qtwebkit-devel # apparently this was deprecated in qt5.6 and was only available until 5.5 or something. see below on how to install

# cmake (DNP3 Support Prerequisite)
sudo yum install -y cmake

# Other prereqs for the above components should build fine with spire

# now, i did not need the following when i used to run with aster servers but with goldenrods its not working otherwise. pretty sure the following are also required so putting them here. All these are not mentioned in the spire docs:

# for pvb:
sudo yum install -y qt5-qtsvg
sudo yum install -y qt5-qtsvg-devel
sudo yum install -y qt5-qttools-devel
sudo yum install -y qt5
sudo yum install -y qt5-qtmultimedia-devel
# qt5-assistant
# even after all above, there were still qt5 related errors with pvb (Project ERROR: Unknown module(s) in QT: uitools webenginewidgets). so i did (takes a while but it is what it is): 
sudo yum install -y qt5-*
# the errors still dont go away
# if we proceed anyway (including ./install.sh). pvbrowser.desktop gives errors after install and doesnt do anything without install
# i think the issue has been qt5-qtwebkit-devel which is no longer available with yum install (deprecated or something). so: download these two: 
# https://rhel.pkgs.org/9/epel-x86_64/qt5-qtwebkit-5.212.0-0.75alpha4.el9.x86_64.rpm.html 
# https://rhel.pkgs.org/9/epel-x86_64/qt5-qtwebkit-devel-5.212.0-0.75alpha4.el9.x86_64.rpm.html
# wget is not working on goldenrods. probably a proxy issue
# then install:
# sudo dnf install filename1
# sudo dnf install filename2
# lol. still the same issue
# uitools issue goes away with qt5-devel but that is not present in the default repo that yum uses on alma linux. so need to enable a diff repo. use:
dnf --enablerepo=crb install qt5-devel
# this still remains 'Project ERROR: Unknown module(s) in QT: webenginewidgets'
# after that i ran the following command and that made the webenginewidgets error go away. 
sudo yum install qt5* --skip-broken
# There is still (seemingly minor) issue that was there before too:
# "
# on the OpenSUSE buildservice you may ignore missing csh error because
# there we use the standard qmake and not our own fake_qmake
# ./rlbuild-all.sh: ./rlcompile-fake-qmake.sh: /bin/csh: bad interpreter: No such file or directory
# "
# seems to be working fine otherwise though (after running it from all apps screen, see below)

# apparently need to launch pvbrowser from all apps menu and not from files app or terminal:
# https://stackoverflow.com/questions/50412577/cant-run-executables-from-nautilus
# so copy the file to this dir. then run from all apps.
# cp /home/hun13/spire/pvb/pvbrowser.desktop $HOME/.local/share/applications

# i guess i should look at what are the the least amount of qt5 related packages that i need to install.

# for openplc:
sudo yum install -y autoconf
sudo yum install -y automake
sudo yum install -y bison