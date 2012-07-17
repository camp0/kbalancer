#define MAX_NAME 32

#define KBALANCER_IOADDDEV 0
#define KBALANCER_IODELDEV 1
#define KBALANCER_IOMODDEV 2
#define KBALANCER_IOSETQOS 3
#define KBALANCER_IOADDRULE 4
#define KBALANCER_IODELRULE 5
#define KBALANCER_IORESET 6
#define KBALANCER_IOINITQOS 7 
#define KBALANCER_IOADAPON 8
#define KBALANCER_IOADAPOFF 9 

#define DEVICE_POLICY_NEMO 0
#define DEVICE_POLICY_MASTER 1 
#define DEVICE_POLICY_SLAVE 2 

struct user_kbalancer_dev  {
        char dev_name[MAX_NAME];
        int policy;
        int bid;
        int link_quality;
};

struct user_kbalancer_rule {
        int protocol;
        int destination_port;
        int to_device;
};
