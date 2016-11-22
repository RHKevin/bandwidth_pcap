//
//  main.c
//  bandwidth_pcap
//
//  Created by Kevin on 2016/11/20.
//  Copyright © 2016年 Kevin. All rights reserved.
//

#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <netinet/in.h>

#define FILTER_MAX 256
#define IN         (u_char *)1
#define OUT        (u_char *)2

static long totalBytes_in, totalBytes_out;
static struct timeval startTime_in, startTime_out;
static double speed_in, speed_out;
pcap_t *handle_in, *handle_out;

pthread_mutex_t mutex_in   = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_out  = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  cond_in    = PTHREAD_COND_INITIALIZER;
pthread_cond_t  cond_out   = PTHREAD_COND_INITIALIZER;

volatile sig_atomic_t run_in  = 1;
volatile sig_atomic_t run_out = 1;

void* in_thread(void *);
void* out_thread(void *);
void handler_thread(u_char *);
void handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char * argv[]) {

    struct ifaddrs *addr, *addr_header;
    char *dev, errbuf_in[PCAP_ERRBUF_SIZE], errbuf_out[PCAP_ERRBUF_SIZE];
    char filter_ip[FILTER_MAX];
    int error;
    pthread_t in, out;
    sigset_t new, old;
    
    if ( argc == 1 ) {
        dev = pcap_lookupdev(errbuf_in);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf_in);
            return(2);
        }
    } else
        dev = argv[1];
    
    if ( getifaddrs(&addr_header) != 0 ) {
        perror("getifaddrs error");
        return 2;
    }
    
    addr = addr_header;
    
    while ( addr != NULL ) {
        if ( strcmp(addr->ifa_name, dev) == 0 ) {
            struct sockaddr *sd = (struct sockaddr*)addr->ifa_addr;
            char str_addr[INET6_ADDRSTRLEN];
            const char *res = NULL;
            
            if ( sd->sa_family == AF_INET )
                res = inet_ntop(AF_INET, &((struct sockaddr_in*)sd)->sin_addr, str_addr, INET6_ADDRSTRLEN);
            
            if ( sd->sa_family == AF_INET6 )
                res = inet_ntop(AF_INET6, &((struct sockaddr_in6*)sd)->sin6_addr, str_addr, INET6_ADDRSTRLEN);
            
            if ( res != NULL ) {
                sprintf(filter_ip, "%s %s or", filter_ip, str_addr);
            }
        }
        addr = addr->ifa_next;
    }
    
    freeifaddrs(addr_header);
    
    *(filter_ip + strlen(filter_ip) - 2) = 0; //remove last 'or'
    
    handle_in = pcap_open_live(dev, BUFSIZ, 0, 100/* See Below */, errbuf_in);
    if ( handle_in == NULL ) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf_in);
        return(2);
    }
    /*
     Quoted From Man Page:
     
         Note also that, in a  multi-threaded  application,  if  one  thread  is
         blocked    in    pcap_dispatch(),    pcap_loop(),    pcap_next(),    or
         pcap_next_ex(), a call to pcap_breakloop() in a different  thread  will
         not unblock that thread; you will need to use whatever mechanism the OS
         provides for breaking a thread  out  of  blocking  calls  in  order  to
         unblock the thread, such as thread cancellation in systems that support
         POSIX threads.
     
     But in this program, pcap_breakloop() does work in muti-threaded, just got a delay(= pcap_open_live() timeout) to break.
     
     Back to man page:
     
        This routine is safe to use inside a signal handler on UNIX or  a  console
        control  handler  on  Windows,  as  it merely sets a flag that is
        checked within the loop.
     
     And this article seems reasonble:
        
        https://www.mail-archive.com/winpcap-users@winpcap.polito.it/msg01645.html
        “Since I don't see any problems in setting a flag in a structure (this is
        what pcap_breakloop() does) from a different thread, I'm inclined to
        interpret this statement as "pcap_breakloop() can be invoked from another
        execution entity, like for example a different thread", and in fact console
        control handlers in Windows, if I remember well, are implmented as separate
        threads.
     
        The statement is intended to be interpreted as "it doesn't modify a data structure in ways that will cause problems if
        another thread is also reading or writing the data structure". It doesn't guarantee that a blocking kernel trap will
        be interrupted, however, which is why the documentation says it won't unblock the thread. On UNIX systems, if it's called from
        a signal handler, the signal itself should unblock the kernel trap (causing it to return -1 an dset "errno" to EINTR), at
        least in a single-threaded program. That won't necessarily be the case on Windows.”
     
     So, my interpretaion is, pcap_breakloop() from other thread just set the break flag of the specific pcap loop, but it doesn't
     break that loop immediately, when current pcap_live expired(pacap loop simply consists of many pcap_lives), the loop round back and check the break flag and found it should break, so, there is a delay between pcap_breakloop() and real break, and a lower pcap_live timeout can reduce this latency.
    */
    
    handle_out = pcap_open_live(dev, BUFSIZ, 0, 100, errbuf_out);
    if ( handle_out == NULL ) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf_out);
        return(2);
    }
    
    //Set Filter
    if ( strlen(filter_ip) != 0 ) {  //If NIC dosen't have a valid IP address, don't use filters.
        
        char filter[FILTER_MAX];
        struct bpf_program fp;
        
        //In
        sprintf(filter, "dst host %s", filter_ip);
      
        if ( pcap_compile(handle_in, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1 ) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle_in));
            return(2);
        }
        
        
        if ( pcap_setfilter(handle_in, &fp) == -1 ) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle_in));
            return(2);
        }
        
        //Out
        sprintf(filter, "src host %s", filter_ip);

        if ( pcap_compile(handle_out, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1 ) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle_out));
            return(2);
        }
        
        if ( pcap_setfilter(handle_out, &fp) == -1 ) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle_out));
            return(2);
        }
        
    } else {
        fprintf(stderr, "%s does't have a valid IP address", dev);
    }
    
    totalBytes_in = totalBytes_out = 0;
    
    sigemptyset(&new);
    sigaddset(&new, SIGALRM);
    
    if ( (error = pthread_sigmask(SIG_BLOCK, &new, &old)) != 0 ) {  //Block SIGALRM;
        fprintf(stderr, "SIG_BLOCK error%s\n", strerror(error));
        return 2;
    }
    
    if ( (error = pthread_create(&in, NULL, in_thread, NULL)) != 0 ) {
        fprintf(stderr, "pthread_create error %s", strerror(error));
        return -1;
    }
    
    if ( (error = pthread_create(&out, NULL, out_thread, NULL)) != 0 ) {
        fprintf(stderr, "pthread_create error %s", strerror(error));
        return -1;
    }

    int signo;
    
    while ( 1 ) {

        error = sigwait(&new, &signo);
        if ( error != 0 ) {
            fprintf(stderr, "sigwait error%s\n", strerror(error));
            break;
        }
        
        if ( signo != SIGALRM ) {
            fprintf(stderr, "unexpected signal\n");
            continue;
            //break; //some xcode magics cause an unknown signal the first time sigwait start(or maybe first time sigalrm occured). so I have to replace it with continue for run in xcode.
        }
        
        pcap_breakloop(handle_in);
        pcap_breakloop(handle_out);
        
        char *format_in, *format_out;
        double _speed_in, _speed_out;
        
        pthread_mutex_lock(&mutex_in);
        pthread_mutex_lock(&mutex_out); //Waiting threads til all of them unlock mutex.(i.e: just finished calculation period or finished it and enter waiting for run condition stage.)
        
        _speed_in = speed_in;
        _speed_out = speed_out;
        
        run_in = 1;                 //set run condition to true;
        run_out = 1;
        
        pthread_cond_signal(&cond_in);
        pthread_cond_signal(&cond_out);
        
        pthread_mutex_unlock(&mutex_in);
        pthread_mutex_unlock(&mutex_out);
        
        if ( _speed_in > 1024 ) {
            _speed_in /= 1024.0;
            format_in = "MB/s";
        } else {
            format_in = "KB/s";
        }
        
        if ( _speed_out > 1024 ) {
            _speed_out /= 1024.0;
            format_out = "MB/s";
        } else {
            format_out = "KB/s";
        }
    
        printf("In: %7.2f %4s | Out: %7.2f %4s\r", _speed_in, format_in, _speed_out, format_out);
        fflush(stdout);
    }
    
    pthread_cond_destroy(&cond_in);
    pthread_cond_destroy(&cond_out);
    pthread_mutex_destroy(&mutex_in);
    pthread_mutex_destroy(&mutex_out); //maybe should inside thread clean functions.
    
    pthread_cancel(in);
    pthread_cancel(out);
    //Here cancel can cancel thread immediately, thought no explicit cancel point. May caused by pcap_loop().
    
    pthread_join(in, NULL);
    pthread_join(out, NULL);
    
    pcap_close(handle_in);
    pcap_close(handle_out);

    return 0;
}

void* in_thread(void *argv) {
    handler_thread(IN);
    pthread_exit((void *)-1); //handler_thread return means error occurred.
}

void* out_thread(void *argv) {
    handler_thread(OUT);
    pthread_exit((void *)-1);
}

void handler_thread(u_char *argv) {
    struct timeval *startTime;
    pcap_t *p;
    double *speed;
    long *totalBytes;
    pthread_mutex_t *mutex;
    pthread_cond_t *cond;
    volatile sig_atomic_t *run;
    
    if ( argv == IN ) {
        totalBytes = &totalBytes_in;
        startTime = &startTime_in;
        speed = &speed_in;
        mutex = &mutex_in;
        cond = &cond_in;
        p = handle_in;
        run = &run_in;
    } else if ( argv == OUT ) {
        totalBytes = & totalBytes_out;
        startTime = &startTime_out;
        speed = &speed_out;
        mutex = &mutex_out;
        cond = &cond_out;
        p = handle_out;
        run = &run_out;
    } else {
        fprintf(stderr, "invalid argument");
        return;
    }
    
    while ( 1 ) {

        pthread_mutex_lock(mutex);
        while ( !(*run) )
            pthread_cond_wait(cond, mutex);  //Waiting main thread finish its speed value reading.
        *run = 0;
        
        alarm(1);
        gettimeofday(startTime, NULL);
        int x = pcap_loop(p, -1, handler, argv);
        if ( x == -1 ) {
            fprintf(stderr, "pcap_loop error %s\n", pcap_geterr(p));
            return;
        }
     
        if ( x == -2 ) {
            struct timeval endTime;
            gettimeofday(&endTime, NULL);
            double duration = endTime.tv_sec - startTime->tv_sec + (endTime.tv_usec - startTime->tv_usec) / 1000.0 / 1000.0;
            *speed = *totalBytes / 1024.0 / duration;
            *totalBytes = 0;
        }
        
        pthread_mutex_unlock(mutex);  //Unlock mutex for main thread reading speed values.
    }
    
}

void handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    if ( user == IN )
        totalBytes_in += header->len;
    if ( user == OUT )
        totalBytes_out += header->len;
}
