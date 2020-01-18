
Links

    Linux kernel network hooks
        https://medium.com/@GoldenOak/linux-kernel-communication-part-1-netfilter-hooks-15c07a5a5c4e

    Using NFQUEUE and libnetfilter_queue
        https://www.andersoncalixto.com.br/2015/11/using-nfqueue-and-libnetfilter_queue
        
Commands:

    sudo insmod net_filter.ko - install kernel module

    sudo rmmod net_filter - remove kernel module
    
    lsmod - list kernel modules
    
    dmesg -w | grep net_filter - display printk logs for net_filter


Types of kernel network filter hooks

    [Incoming Packet]--->[1]--->[ROUTE]--->[3]--->[4]--->[Outgoing Packet]
                                   |            ^
                                   |            |
                                   |         [ROUTE]
                                   v            |
                                  [2]          [5]
                                   |            ^
                                   |            |
                                   v            |
                                   
                     
    1.NF_IP_PER_ROUNTING
        This hook is called when a packet arrives into the machine.
            
    2.NF_IP_LOCAL_IN 
        This hook is called when a packet is destined to the machine itself.
            
    3.NF_IP_FORWARD
        This hook is called when a packet is destined to another interface.
        
    4.NF_IP_POST_ROUTING 
        Is called when a packet is on its way back to the wire and outside the machine.
        
    5.NF_IP_LOCAL_OUT 
        When a packet is created locally, and is destined out, this hook is called.
    

Hook callback return values (linux/netfilter.h)

    1. NF_DROP - Drop the packet
    2. NF_ACCEPT - Release packet
    3. NF_QUEUE - Queue for user space handling


Kernel version note
    Tested on [5.0.0-37-generic] kernel build.
    To test kernel release version on a machine run "uname -r".


