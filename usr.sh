#!/bin/bash

function print
{
	tmp=`bpftool map lookup id $1 key $2 0 0 0`
	tmp_2=`echo ${tmp:24}`
 	to_dec $tmp_2
}
function to_dec
{	
	res=0;
	pos=0
	len=2
	tmp=`echo ${1:pos:len}`
	tmp_2=`echo $((16#$tmp))`
	let "res = res + tmp_2"
	tmp=`echo ${2:pos:len}`
	tmp_2=`echo $((16#$tmp))`
	let "res = res + tmp_2*16*16"
	tmp=`echo ${3:pos:len}`
	tmp_2=`echo $((16#$tmp))`
	let "res = res + tmp_2*16*16*16"
	tmp=`echo ${4:pos:len}`
	tmp_2=`echo $((16#$tmp))`
	let "res = res + tmp_2*16*16*16*16"
	echo $res
}
bpftool map show
echo "Input id of needed table"
read id_
echo "Input one of the following lines:"
echo "NONIP"
echo "TCPIP"
echo "TCPIP6"
echo "UDPIP"
echo "UDPIP6"
echo "VLAN"
echo "NONVLAN"
echo "OTHER"
echo "OTHER6"
echo "STOP"
echo
while true
do
	read type_
	if [[ $type_ == "NONIP" ]]
	then	
		print $id_ 0x0
	fi
	if [[ $type_ == "TCPIP" ]]
	then
		print $id_ 0x1
	fi
	if [[ $type_ == "TCPIP6" ]]
	then
		print $id_ 0x2	
	fi
	if [[ $type_ == "UDPIP" ]]
	then
		print $id_ 0x3
	fi
	if [[ $type_ == "UDPIP6" ]]
	then
		print $id_ 0x4
	fi
	if [[ $type_ == "VLAN" ]]
	then
		print $id_ 0x5
	fi
	if [[ $type_ == "NONVLAN" ]]
	then
		print $id_ 0x6
	fi
	if [[ $type_ == "OTHER" ]]
	then
		print $id_ 0x7
	fi
	if [[ $type_ == "OTHER6" ]]
	then
		print $id_ 0x8
	fi	
	if [[ $type_ == "STOP" ]]
	then
		exit
	fi
done
