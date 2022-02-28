#!/bin/bash
#set -x
#insert data for connection to misp,memcached and directory to error log
LOG="/var/tmp/telnnet_conn.log"
#HOSTS -> for memcached
HOSTS="0.0.0.0
1.1.1.1" #insert hosts 
#MISP -> for misp
MISP="0.0.0.0" #insert misp ip 
#TOKEN from MISP 
TOKEN="blahblahblah" #misp_token
PORT="$PORT"
VICTIM=$VICTIM
#Select what you are going to delete

echo "Select smth to kill:"
echo "1 to kill hash"
echo "2 to kill ip"
echo "3 to kill domain"
echo -n "Enter victim: "
read VICTIM 
case $VICTIM in


  1)
    #PORT FOR HASH
    PORT=11211 
    echo -n "throw me some hash:"
    read HASH 
    echo -n "throw me rulename:"
    read RULE
    VICTIM=$HASH
    #Deleting from misp using api and curl 
    if [ ${#VICTIM} -eq 32 ]; then
        #Request for UUID of IOC
	request=$(curl --location --request POST 'https://'$MISP'/attributes/restSearch' --header 'Authorization:'$TOKEN --header 'verify:false' --header 'Accept:application/json' --header 'Content-Type:application/json' --data '{"returnFormat":"json","type":"md5","value":'\"$VICTIM\"',"eventinfo":'\""$RULE"\"'}' -k  |python -c 'import json, sys;obj=json.load(sys.stdin);print obj["response"]["Attribute"][0]["uuid"]') >> $LOG && > $LOG 
 	echo $request
	#Request for Event where  IOC is stored
 	id=$(curl --location --request POST 'https://'$MISP'/attributes/restSearch' --header 'Authorization:'$TOKEN --header 'verify:false' --header 'Accept:application/json' --header 'Content-Type:application/json' --data '{"returnFormat":"json","type":"md5","value":'\"$VICTIM\"',"eventinfo":'\""$RULE"\"'}' -k |python -c 'import json, sys;obj=json.load(sys.stdin);print obj["response"]["Attribute"][0]["Event"]["id"]') >> $LOG && > $LOG
    	echo $id
	#Request for deleting FP  IOC
   	deleting=$(curl --location --request POST 'https://'$MISP'/attributes/delete/'$request -k --header 'Authorization:'$TOKEN --header 'verify:false' --header 'Accept:application/json' --header 'Content-Type:application/json') >> $LOG && > $LOG
   	echo $deleting
	#Request for publishing Event in MISP
	publish_misp=$(curl --location --request POST 'https://'$MISP'/events/publish/'$id --header 'Authorization:'$TOKEN --header 'verify:false' --header 'Accept:application/json' --header 'Content-Type:application/json' -k) >> $LOG && > $LOG
   	echo $publish_misp
	VICTIM=md5-$VICTIM
    elif [ ${#VICTIM} -eq 40 ]; then
        request=$(curl --location --request POST 'https://'$MISP'/attributes/restSearch' --header 'Authorization:'$TOKEN --header 'verify:false' --header 'Accept:application/json' --header 'Content-Type:application/json' --data '{"returnFormat":"json","type":"sha1","value":'\"$VICTIM\"',"eventinfo":'\""$RULE"\"'}' -k  |python -c 'import json, sys;obj=json.load(sys.stdin);print obj["response"]["Attribute"][0]["uuid"]') >> $LOG && > $LOG 
 	echo $request
 	id=$(curl --location --request POST 'https://'$MISP'/attributes/restSearch' --header 'Authorization:'$TOKEN --header 'verify:false' --header 'Accept:application/json' --header 'Content-Type:application/json' --data '{"returnFormat":"json","type":"sha1","value":'\"$VICTIM\"',"eventinfo":'\""$RULE"\"'}' -k |python -c 'import json, sys;obj=json.load(sys.stdin);print obj["response"]["Attribute"][0]["Event"]["id"]') >> $LOG && > $LOG
    	echo $id
   	deleting=$(curl --location --request POST 'https://'$MISP'/attributes/delete/'$request -k --header 'Authorization:'$TOKEN --header 'verify:false' --header 'Accept:application/json' --header 'Content-Type:application/json') >> $LOG && > $LOG
   	echo $deleting
	publish_misp=$(curl --location --request POST 'https://'$MISP'/events/publish/'$id --header 'Authorization:'$TOKEN --header 'verify:false' --header 'Accept:application/json' --header 'Content-Type:application/json' -k) >> $LOG && > $LOG
   	echo $publish_misp
	VICTIM=sha1-$VICTIM
    elif [ ${#VICTIM} -eq 64 ]; then
        request=$(curl --location --request POST 'https://'$MISP'/attributes/restSearch' --header 'Authorization:'$TOKEN --header 'verify:false' --header 'Accept:application/json' --header 'Content-Type:application/json' --data '{"returnFormat":"json","type":"sha256","value":'\"$VICTIM\"',"eventinfo":'\""$RULE"\"'}' -k  |python -c 'import json, sys;obj=json.load(sys.stdin);print obj["response"]["Attribute"][0]["uuid"]') >> $LOG && > $LOG 
 	echo $request
 	id=$(curl --location --request POST 'https://'$MISP'/attributes/restSearch' --header 'Authorization:'$TOKEN --header 'verify:false' --header 'Accept:application/json' --header 'Content-Type:application/json' --data '{"returnFormat":"json","type":"sha256","value":'\"$VICTIM\"',"eventinfo":'\""$RULE"\"'}' -k |python -c 'import json, sys;obj=json.load(sys.stdin);print obj["response"]["Attribute"][0]["Event"]["id"]') >> $LOG && > $LOG
    	echo $id
   	deleting=$(curl --location --request POST 'https://'$MISP'/attributes/delete/'$request -k --header 'Authorization:'$TOKEN --header 'verify:false' --header 'Accept:application/json' --header 'Content-Type:application/json') >> $LOG && > $LOG
   	echo $deleting
	publish_misp=$(curl --location --request POST 'https://'$MISP'/events/publish/'$id --header 'Authorization:'$TOKEN --header 'verify:false' --header 'Accept:application/json' --header 'Content-Type:application/json' -k) >> $LOG && > $LOG
   	echo $publish_misp
	VICTIM=sha256-$VICTIM
    else 
	echo "smth went wrong" 
    fi
    ;;

  2)
    #PORT FOR ip,domain...
    PORT=11212
    echo -n "throw me some ip:"
    read IP 
    VICTIM=$IP
 
    if [[ $VICTIM =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    VICTIM=ip-dst-$VICTIM
    echo -n "throw me rule name:"
    read RULE
    echo $RULE 
    request=$(curl --location --request POST 'https://'$MISP'/attributes/restSearch' --header 'Authorization:'$TOKEN --header 'verify:false' --header 'Accept:application/json' --header 'Content-Type:application/json' --data '{"returnFormat":"json","type":"ip-dst","value":'\"$IP\"',"eventinfo":'\""$RULE"\"'}' -k  |python -c 'import json, sys;obj=json.load(sys.stdin);print obj["response"]["Attribute"][0]["uuid"]') >> $LOG && > $LOG 
    echo $request
    id=$(curl --location --request POST 'https://'$MISP'/attributes/restSearch' --header 'Authorization:'$TOKEN --header 'verify:false' --header 'Accept:application/json' --header 'Content-Type:application/json' --data '{"returnFormat":"json","type":"ip-dst","value":'\"$IP\"',"eventinfo":'\""$RULE"\"'}' -k |python -c 'import json, sys;obj=json.load(sys.stdin);print obj["response"]["Attribute"][0]["Event"]["id"]') >> $LOG && > $LOG
    echo $id
    deleting=$(curl --location --request POST 'https://'$MISP'/attributes/delete/'$request -k --header 'Authorization:'$TOKEN --header 'verify:false' --header 'Accept:application/json' --header 'Content-Type:application/json') >> $LOG && > $LOG
    echo $deleting
    deleting_misp=$(curl --location --request POST 'https://'$MISP'/events/publish/'$id --header 'Authorization:'$TOKEN --header 'verify:false' --header 'Accept:application/json' --header 'Content-Type:application/json' -k) >> $LOG && > $LOG
    echo $deleting_misp
    else echo "Wrong IP-adress" && exit;
    fi
    ;;

   3)
    #PORT FOR ip,domain...
    PORT=11212
    echo -n "throw me some domain:"
    read DOMAIN 
    echo -n "throw me rulename:"
    read RULE
     request=$(curl --location --request POST 'https://'$MISP'/attributes/restSearch' --header 'Authorization:'$TOKEN --header 'verify:false' --header 'Accept:application/json' --header 'Content-Type:application/json' --data '{"returnFormat":"json","type":"domain","value":'\"$DOMAIN\"',"eventinfo":'\""$RULE"\"'}' -k  |python -c 'import json, sys;obj=json.load(sys.stdin);print obj["response"]["Attribute"][0]["uuid"]') >> $LOG && > $LOG 
    echo $request
    id=$(curl --location --request POST 'https://'$MISP'/attributes/restSearch' --header 'Authorization:'$TOKEN --header 'verify:false' --header 'Accept:application/json' --header 'Content-Type:application/json' --data '{"returnFormat":"json","type":"domain","value":'\"$DOMAIN\"',"eventinfo":'\""$RULE"\"'}' -k |python -c 'import json, sys;obj=json.load(sys.stdin);print obj["response"]["Attribute"][0]["Event"]["id"]') >> $LOG && > $LOG
    echo $id
    deleting=$(curl --location --request POST 'https://'$MISP'/attributes/delete/'$request -k --header 'Authorization:'$TOKEN --header 'verify:false' --header 'Accept:application/json' --header 'Content-Type:application/json') >> $LOG && > $LOG
    echo $deleting
    deleting_misp=$(curl --location --request POST 'https://'$MISP'/events/publish/'$id --header 'Authorization:'$TOKEN --header 'verify:false' --header 'Accept:application/json' --header 'Content-Type:application/json' -k) >> $LOG && > $LOG
    echo $deleting_misp
    VICTIM="domain-"$DOMAIN
    
    ;;
    *) 

	echo "smth went wrong"
	exit 

esac

#telnet to memcached service to delete IOC

for H in $HOSTS
do
echo START SCRIPT: >> $LOG
date +%x-%R >> $LOG
(
sleep 1;
echo "delete $VICTIM";
sleep 1;
) | telnet $H $PORT >> $LOG && > $LOG 
echo =================================== >> $LOG
tail -n 2 $LOG
done

