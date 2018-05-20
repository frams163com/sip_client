// compile with gcc -leXosip2 -losip2 -losipparser2 -lpthread

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h> // check stdin
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>
#include <pthread.h>
#include <string.h>
#include <signal.h>

#include <eXosip2/eXosip.h>

#define P(x)  printf(x"\n");
#define Pn(x) printf(#x" = %d\n",x)
#define Ps(x) printf(#x" = %s\n",x)

typedef struct regparam_t
{
    int regid;
    int expiry;
    int auth;
} regparam_t;

struct eXosip_t *ctx;

// check availability of stdin
int inputAvailable()
{
    struct timeval tv;
    fd_set fds;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    select(STDIN_FILENO+1, &fds, NULL, NULL, &tv);
    return (FD_ISSET(0, &fds));
}

void make_call(struct eXosip_t* context_eXosip, char* from, char* to, char* localip)
{
    osip_message_t *invite;
    int cid;
    int err;
    printf("%s\n",from);
    printf("%s\n",to);
    err = eXosip_call_build_initial_invite (context_eXosip, &invite, 
                                            to,
                                            from,
                                            NULL, // optional route header
                                            "This is a call for a conversation");
    Pn(err);
    char tmp[4096];
    snprintf (tmp, 4096,
              "v=0\r\n"
              "o=anystr 0 0 IN IP4 %s\r\n"
              "s=conversation\r\n"
              "c=IN IP4 %s\r\n"
              "t=0 0\r\n"
              "m=audio %s RTP/AVP 0 8 101\r\n"
              "a=rtpmap:0 PCMU/8000\r\n"
              "a=rtpmap:8 PCMA/8000\r\n"
              "a=rtpmap:101 telephone-event/8000\r\n"
              "a=fmtp:101 0-11\r\n", localip, localip, "5060");
    printf("%s\n", tmp);
    // osip_message_set_body (invite, tmp, strlen (tmp));
    osip_message_set_body (invite, tmp);
    osip_message_set_content_type (invite, "application/sdp");

    eXosip_lock (context_eXosip);
    cid = eXosip_call_send_initial_invite (context_eXosip, invite);
    eXosip_unlock (context_eXosip);
    // free(invite)
    // osip_free(invite)
}


int main (int argc, char *argv[])
{
    int port = 5060;
    char *contact = NULL;
    char *fromuser = NULL;
    char *proxy = NULL;
    char* localip;
    char transport[5] = "UDP";
    char *username = NULL;
    char *password = NULL;
    struct regparam_t regparam = { 0, 60, 0 }; // 3600
    int err;

    proxy    = strdup("sip:192.168.1.114");
    fromuser = strdup("sip:111@192.168.1.114");
    localip  = strdup("192.168.1.113");
    username = strdup("111");
    password = strdup("abc123456");
    
    ctx = eXosip_malloc ();
    err = eXosip_init (ctx);
    err = eXosip_listen_addr (ctx, IPPROTO_UDP, NULL, port, AF_INET, 0);
    err = eXosip_add_authentication_info (ctx, username, username, password, NULL, NULL);
    osip_message_t *reg = NULL;
    regparam.regid = eXosip_register_build_initial_register (ctx, fromuser, proxy, contact, regparam.expiry * 2, &reg);
    err = eXosip_register_send_register (ctx, regparam.regid, reg);

    int c;
    for (;;)
    {
        eXosip_event_t *event;

        if (!(event = eXosip_event_wait (ctx, 1, 10)))
        {
            eXosip_automatic_action (ctx);
            P("it_s null");
            if( inputAvailable() )
            {
                P("making call");
                c = getchar();
                c = getchar();
                char* from;
                from = (char*) malloc(256);
                sprintf(from,"<%s>",fromuser);
                printf("%s\n",from);
                char* to;
                to = strdup("<sip:333@192.168.1.114>"); //scanf("%s",to);
                make_call(ctx, from, to, localip);
            }
            continue;
        }

        eXosip_lock (ctx);
        printf("ev-type %d\n", event->type);
        switch (event->type)
        {
        case EXOSIP_REGISTRATION_SUCCESS:
            P("registrered successfully");
            break;
        case EXOSIP_REGISTRATION_FAILURE:
            P("REGISTRATION_FAILURE");
            break;
        case EXOSIP_CALL_INVITE:
        {
            P("call invite");
            osip_message_t *answer;
            err = eXosip_call_build_answer (ctx, event->tid, 180, &answer);
            err = eXosip_call_send_answer (ctx, event->tid, 180, answer);
            P("INVITE respond 180");
            // err = sdp_complete_200ok (event->did, answer);
            P("sleep 1s to make sure transfer completed");
            sleep(1);
            err = eXosip_call_build_answer (ctx, event->tid, 200, &answer);
            err = eXosip_call_send_answer (ctx, event->tid, 200, answer);
            P("INVITE respond 200");
            break;
        }
        case EXOSIP_MESSAGE_NEW:
        {
            P("msg new");
            osip_message_t *answer;

            err = eXosip_message_build_answer (ctx, event->tid, 405, &answer);
            err = eXosip_message_send_answer (ctx, event->tid, 405, answer);
            P("EXOSIP_MESSAGE_NEW rejected with 405");
            break;
        }
        case EXOSIP_IN_SUBSCRIPTION_NEW:
        {
            P("sub new");
            osip_message_t *answer;

            err = eXosip_insubscription_build_answer (ctx, event->tid, 405, &answer);
            err = eXosip_insubscription_send_answer (ctx, event->tid, 405, answer);
            P("EXOSIP_IN_SUBSCRIPTION_NEW rejected with 405");
            break;
        }
        default:
        {
            P("---default");
            eXosip_automatic_action (ctx);
            printf("recieved eXosip event (type, did, cid) = (%d, %d, %d)", event->type, event->did, event->cid);
        }
        }
        eXosip_unlock (ctx);
        P("-----end");
        P();
        eXosip_event_free (event);
    }

    eXosip_quit (ctx);
    return 0;
}
