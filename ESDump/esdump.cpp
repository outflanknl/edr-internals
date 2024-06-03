#include <EndpointSecurity/EndpointSecurity.h>
#include <signal.h>
#include <unistd.h>

#include "config.h"
#include "esdump.h"

constexpr int EVENT_COUNT = sizeof(TARGET_EVENTS) / sizeof(TARGET_EVENTS[0]);

void log_event(es_client_t* c, const es_message_t* m) {
    auto event_metadata = event_data.at(m->event_type);
    const std::string event_fmt = json{
        {"type", event_metadata.type_name},
        {"data", event_metadata.serialize_fn(m->event)}
    }.dump(JSON_INDENT);

    printf("%s,\n", event_fmt.c_str());

    (void)c;
}

void handle_auth_event(es_client_t* c, const es_message_t* m) {
    log_event(c, m);

    es_respond_result_t ret = es_respond_auth_result(c, m, ES_AUTH_RESULT_ALLOW, false);
    if (ret != ES_RESPOND_RESULT_SUCCESS) {
        printf("ERROR: Failed to respond to authorization event: %d\n", ret);
    }
}

constexpr auto event_handler = ^(es_client_t* c, const es_message_t* m) {
    if (m->action_type == ES_ACTION_TYPE_AUTH) {
        return handle_auth_event(c, m);
    }
    else if (m->action_type == ES_ACTION_TYPE_NOTIFY) {
        return log_event(c, m);
    }

    printf("ERROR: Unknown action type: %d\n", m->action_type);
};

bool create_client(es_client_t** client) {
    es_new_client_result_t ret = es_new_client(client, event_handler);
    if (ret != ES_NEW_CLIENT_RESULT_SUCCESS) {
        if (ret == ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED) {
            printf("ERROR: Root privileges are required to create an ES client\n");
        }
        else if (ret == ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED) {
            printf("ERROR: SIP must be disabled and the binary must have the endpoint security entitlement to create an ES client\n");
        }
        else {
            printf("ERROR: Failed to create an ES client: %d\n", ret);
        }

        return false;
    }

    return true;
}

bool go() {
    es_client_t* client = NULL;
    if (!create_client(&client)) {
        return false;
    }

    es_return_t ret = es_subscribe(client, TARGET_EVENTS, EVENT_COUNT);
    if (ret != ES_RETURN_SUCCESS) {
        printf("ERROR: Failed to subscribe to ES events %d\n", ret);
        return false;
    }

    return true;
}

void stop(int s) {
    printf("Exiting...\n");
    exit(0);
    
    (void)s;
}

int main(int argc, char** argv) {
    struct sigaction sigIntHandler;

    sigIntHandler.sa_handler = stop;

    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;

    sigaction(SIGINT, &sigIntHandler, NULL);

    go();
    pause();

    return 0;

    (void)argc;
    (void)argv;
}
