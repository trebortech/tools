# Tool to deploy local SaltStack vagrant instances

**newMinion.sh** -> This is your base script that requires the **Vagrantfile.conf** to exist in the same directory.

example: newMinion.sh -m MyMinionName -M saltme.trebortech.com -g v2015.5.0

-m|--minionid  ---->  The minion id you would like to assign to this instance. Default: nominionid

-M|--masterurl ---->  The URL to your salt master. Default: master.salt.trebortech.ninja

-g|--git       ---->  The version from salt that you would like to install. Default: v2015.2.0rc2

**Vagrantfile**  -> This is the base vagrantfile that is used to deploy out the vagrant box.

You'll want to update for your personally needs. At the very least you'll want to update the "box" value to utilize an exisitng virtual box image.