#!/bin/bash

while [[ $# >1 ]]
do
key="$1"

case $key in
    -m|--minionid)
    MINION_ID="$2"
    shift
    ;;
    -M|--masterurl)
    MASTER_URL="$2"
    shift
    ;;
    -g|--git)
    GIT_VERSION="$2"
    shift
    ;;
    *)

    ;;
esac
shift
done

#MINION_ID=$1
#MASTER_URL=$2
#GIT_VERSION=$3

: ${MINION_ID:="nominionid"}
: ${MASTER_URL:="master.salt.trebortech.ninja"}
: ${GIT_VERSION:="v2015.2.0rc2"}

mkdir $MINION_ID
cp ./Vagrantfile.conf ./$MINION_ID/Vagrantfile

sed -i '' s/MINION-ID/$MINION_ID/g ./$MINION_ID/Vagrantfile
sed -i '' s/MASTER-URL/$MASTER_URL/g ./$MINION_ID/Vagrantfile
sed -i '' s/GIT-VERSION/$GIT_VERSION/g ./$MINION_ID/Vagrantfile

cd ./$MINION_ID
vagrant up
