# Tool to deploy local SaltStack vagrant instances


This script will use a base image from virtualbox to deploy a new instance out. Once this image comes online it will have the same name as the minionid. The Vagrantfile will need to be modified to be inline with your system requirements. This Vagrantfile is focused on a Ubuntu base system and will update the package repository and create a /stage directory. This directory will have the saltstack bootstrap file in it and will install a salt-minion daemon.

From this point you'll need to do the following.
- Accept the key on your salt master
- Assign the appropiate grains
- Execute a highstate on the new minion.



**newMinion.sh** -> This is your base script that requires the **Vagrantfile.conf** to exist in the same directory.

example:
```
newMinion.sh -m MyMinionName -M saltme.trebortech.com -g v2015.5.0
```

-m|--minionid  ---->  The minion id you would like to assign to this instance. Default: nominionid <br>
-M|--masterurl ---->  The URL to your salt master. Default: master.salt.trebortech.ninja <br>
-g|--git       ---->  The version from salt that you would like to install. Default: v2015.2.0rc2<br> 

**Vagrantfile**  -> This is the base vagrantfile that is used to deploy out the vagrant box.

You'll want to update for your personally needs. At the very least you'll want to update the "box" value to utilize an exisitng virtual box image.

