# xdp_samples
Two programs that can show basics of the XDP. 
1. mss_fix.c

This program will change MSS value of all incoming SYN-TCP packets. 

You can change the final value, default is 1400.
 
This program can show you how to parse and change packet data.
 
 2. count_map.c

This program create a bpf_map which will contain information about number of received packets of each type

It should be used with script usr.sh which will help you to get data from map. 

Notice that you need to install bpftool and run script with sudo


Both programs can be compilated and loaded to the kernel by following way:

    clang -O2 -Wall -target bpf -c FILENAME.c -o sample.o 
 
    sudo ip link set dev <interface_name> xdp obj sample.o
