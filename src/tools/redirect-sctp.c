#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdbool.h> // bool
#include <stdint.h> // uint16t, ...
#include <inttypes.h> // PRIu16, ...
#include <netinet/in.h> // IPPROTO_UDP, IPPROTO_SCTP
#include <unistd.h> // STDIN_FILENO
#include <sys/socket.h> // socket
#include <errno.h> // errno
#include <re.h>
#include <rew.h>

#define DEBUG_MODULE "redirect-sctp"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

#define EXIT_ON_ERROR(code) exit_on_error(code, __FILE__, __LINE__)
#define EXIT_ON_NULL(ptr) exit_on_null(ptr, __FILE__, __LINE__)

static void before_exit() {
    // Close
	libre_close();

	// Check memory leaks
	tmr_debug();
	mem_debug();
}

static void exit_on_error(int code, char const* const file, uint32_t line) {
    if (code != 0) {
        fprintf(stderr, "Error in %s %"PRIu32" (%d): %s\n",
            file, line, code, strerror(code));
        before_exit();
        exit(code);
    }
}

static void exit_on_null(void const* const ptr, char const* const file, uint32_t line) {
    if (ptr == NULL) {
        fprintf(stderr, "Error in %s %"PRIu32": %s\n",
            file, line, "NULL");
        before_exit();
        exit(-1);
    }
}

static int _print_handler(char const* p, size_t size, void* arg) {
    printf("%.*s", (int) size, p);
    return 0;
}

static int _mbuf_handler(char const* p, size_t size, void* buffer) {
    return mbuf_write_mem(buffer, (uint8_t*) p, size);
}

// Static vars
struct re_printf print_handler = {
    .vph = _print_handler,
    .arg = NULL
};
int const component_id = 1;

// Defs
enum {
    COMPONENT_ID = 1
};

enum {
    LAYER_SCTP = 4,
    LAYER_DCEP = 3,
    LAYER_DTLS = 2,
    LAYER_REDIRECT = 1,
	LAYER_ICE = 0,
	LAYER_STUN = -10,
	LAYER_TURN = -10
};

struct candidate_t {
	struct agent_t* agent;
    struct ice_lcand* base;
};

struct agent_t {
    bool offerer;
    struct trice_conf config;
    char ufrag[9];
    char pwd[33];
    struct trice* ice;
    uint32_t pacing_interval;
    bool have_remote;
    struct ice_candpair* selected_pair;
    struct tls* dtls_context;
    struct dtls_sock* dtls_socket;
    struct tls_conn* dtls_connection;
    struct udp_helper* dtls_helper;
    uint32_t packet_counter;
    FILE* wireshark_hex;
    int redirect_socket;
    struct mbuf* redirect_buffer;
    struct sa redirect_address;
};

struct trice_conf default_config = {
    .debug = true,
    .trace = true,
    .ansi = true
};

static uint16_t local_tcp_preference(enum ice_tcptype tcp_type, uint16_t other_preference) {
    uint16_t dir_preference = 0;

    switch (tcp_type) {
        case ICE_TCP_ACTIVE:
            dir_preference = 6;
            break;
        case ICE_TCP_PASSIVE:
            dir_preference = 4;
            break;
        case ICE_TCP_SO:
            dir_preference = 2;
            break;
    }

    return (dir_preference << 13) + other_preference;
}

static uint32_t calculate_priority(
    enum ice_cand_type type, int protocol,
    enum ice_tcptype tcp_type, int af, int turn_protocol)
{
    uint16_t local_preference = 0;

    switch (protocol) {
        case IPPROTO_UDP:
            if (af == AF_INET6) {
                local_preference = turn_protocol == IPPROTO_UDP ? 65535 : 65533;
            } else {
                local_preference = turn_protocol == IPPROTO_UDP ? 65534 : 65532;
            }
            break;

        case IPPROTO_TCP:
            local_preference = local_tcp_preference(tcp_type, af == AF_INET6);
            break;
    }

    return ice_cand_calc_prio(type, local_preference, COMPONENT_ID);
}

static void trace_packet(struct agent_t* const agent, struct mbuf* const buffer) {
    size_t length = mbuf_get_left(buffer);
    if (length == 0) {
        return;
    }
    fprintf(agent->wireshark_hex, "0000");
    uint8_t* buf = mbuf_buf(buffer);
    size_t i;
    for (i = 0; i < length; ++i) {
        fprintf(agent->wireshark_hex, " %02X", buf[i]);
    }
    fprintf(agent->wireshark_hex, "\n\n");
    agent->packet_counter += 1;
    fflush(agent->wireshark_hex);
}

static int add_candidate(
    struct agent_t const* const agent, struct sa const* const address,
    int const protocol, enum ice_tcptype const tcp_type
) {
    // Calculate priority of candidate
    uint32_t priority = calculate_priority(ICE_CAND_TYPE_HOST, protocol, tcp_type, sa_af(address),
        protocol);

    // TODO: Check if interface has already been added
    DEBUG_PRINTF("TODO: Check if interface has already been added\n");

    // Add local candidate
    DEBUG_PRINTF("Adding local candidate %j, type: %s, protocol: %s, priority: %"PRIu32", tcp type: %s\n",
        address, "host", net_proto2name(protocol), priority,
        protocol == IPPROTO_TCP ? ice_tcptype_name(tcp_type) : "n/a");
    struct ice_lcand* local_candidate;
    int error = trice_lcand_add(&local_candidate, agent->ice, COMPONENT_ID, protocol,
        priority, address, NULL, ICE_CAND_TYPE_HOST, NULL, tcp_type, NULL, LAYER_ICE);
    if (error) {
        DEBUG_WARNING("Failed to add local candidate (%m)\n", error);
        return error;
    }

    // TODO: Gather srflx candidates
    DEBUG_PRINTF("TODO: Gather srflx candidates for %j\n", address);
    // TODO: Gather relay candidates
    DEBUG_PRINTF("TODO: Gather relay candidates for %j\n", address);

    return error;
}

static bool interface_handler(char const* const interface, struct sa const* const address, void* const arg) {
    struct agent_t const* const agent = arg;
    DEBUG_PRINTF("Found interface %s: %j", interface, address);
    
    // Link-local?
    re_printf(", link-local: %s", sa_is_linklocal(address) ? "yes" : "no");
    // Loopback?
    re_printf(", loopback: %s", sa_is_loopback(address) ? "yes" : "no");
    // Wildcard?
    re_printf(", wildcard: %s", sa_is_any(address) ? "yes" : "no");
    
    // Ignore loopback and linklocal addresses
    if (sa_is_linklocal(address) || sa_is_loopback(address)) {
        re_printf("\n");
        return false; // Continue gathering
    }

    // Add candidate
    printf("\n");
    EXIT_ON_ERROR(add_candidate(agent, address, IPPROTO_UDP, 0));
    DEBUG_PRINTF("TODO: Add TCP candidate for %j\n", address);
    
    // Continue gathering
    return false;
}

static void redirect_from_machine(int flags, void* const arg) {
    struct agent_t* const agent = arg;
    
    if ((flags & FD_READ) == FD_READ) {
        struct mbuf* buffer = agent->redirect_buffer;
        
        // Rewind buffer
        mbuf_rewind(buffer);
        
        // Receive
        struct sockaddr_in from_address;
        socklen_t from_length = sizeof(struct sockaddr_in);
        ssize_t length = recvfrom(agent->redirect_socket, mbuf_buf(buffer),
            mbuf_get_space(buffer), 0, (struct sockaddr*) &from_address, &from_length);
        if (length == -1) {
            EXIT_ON_ERROR(errno);
        }
        mbuf_set_end(buffer, length);
        
        // Check address
        struct sa from;
        EXIT_ON_ERROR(sa_set_sa(&from, (struct sockaddr*) &from_address));
        DEBUG_PRINTF("Received %zu bytes via RAW from %j\n", mbuf_get_left(buffer), &from);
        if (!sa_isset(&from, SA_ADDR) && !sa_cmp(&agent->redirect_address, &from, SA_ADDR)) {
            DEBUG_WARNING("Ignored data from unknown address!\n");
            return;
        }
        
        // Skip IPv4 header
        size_t header_length = (mbuf_read_u8(buffer) & 0xf);
        mbuf_advance(buffer, -1);
        DEBUG_PRINTF("RAW IPv4 header length: %zu\n", header_length);
        mbuf_advance(buffer, header_length * 4);
        trace_packet(agent, buffer);
        
        // Send data
        DEBUG_INFO("Sending %zu bytes via DTLS connection\n", mbuf_get_left(buffer));
        int error = dtls_send(agent->dtls_connection, buffer);
        if (error) {
            DEBUG_WARNING("Could not send, error: %m\n", error);
        }
    }
}

static void redirect_to_machine(struct agent_t* const agent, struct mbuf* const buffer) {
    // Send
    DEBUG_PRINTF("Sending %zu bytes via RAW to %j\n", mbuf_get_left(buffer),
        &agent->redirect_address);
    ssize_t length = sendto(agent->redirect_socket, mbuf_buf(buffer), mbuf_get_left(buffer),
        0, &agent->redirect_address.u.sa, agent->redirect_address.len);
    if (length == -1) {
        EXIT_ON_ERROR(errno);
    }
    mbuf_advance(buffer, length);
}

static bool dtls_send_helper(int* err, struct sa* original_destination, struct mbuf* const buffer, void* const arg) {
    struct agent_t* const agent = arg;
    
    // Send on selected candidate pair
    struct udp_sock* const udp_socket = trice_lcand_sock(agent->ice, agent->selected_pair->lcand);
    EXIT_ON_NULL(udp_socket);
    struct sa const* const source = &agent->selected_pair->lcand->attr.addr;
    EXIT_ON_NULL(source);
    struct sa const* const destination = &agent->selected_pair->rcand->attr.addr;
    EXIT_ON_NULL(destination);
    DEBUG_PRINTF("Relaying DTLS packet of %zu bytes to %J (originally: %J) from %J\n",
        mbuf_get_left(buffer), destination, original_destination, source);
    // TODO: I'm guessing here that err can be used to propagate the error code... ?
    *err |= udp_send(udp_socket, destination, buffer);
    if (*err) {
        DEBUG_WARNING("Could not send, error: %m\n", err);
    }
    // TODO: Should we return true in error case as well?
    return true;
}

static void dtls_close_handler(int err, void* const arg) {
    (void)(arg);
    DEBUG_WARNING("dtls_close_handler(err: %m)\n", err);
    EXIT_ON_ERROR(err);
}

static void dtls_receive_handler(struct mbuf* const buffer, void *arg) {
    struct agent_t* const agent = arg;
    DEBUG_PRINTF("Received %zu bytes via DTLS connection\n", mbuf_get_left(buffer));
    trace_packet(agent, buffer);
    redirect_to_machine(agent, buffer);
}

static void dtls_establish_handler(void *arg) {
    (void)(arg);
    DEBUG_INFO("DTLS connection established\n");
}

static void dtls_connect_handler(const struct sa* const peer, void* const arg) {
    struct agent_t* const agent = arg;
    
    if (agent->offerer && agent->dtls_connection == NULL) {
        // Accept peer and verify certificate
        DEBUG_PRINTF("DTLS accept: %J\n", peer);
        EXIT_ON_ERROR(dtls_accept(&agent->dtls_connection, agent->dtls_context, agent->dtls_socket,
            dtls_establish_handler, dtls_receive_handler, dtls_close_handler, agent));
        DEBUG_PRINTF("Verifying peer's certificate\n");
        EXIT_ON_ERROR(tls_peer_verify(agent->dtls_connection));
    } else {
        DEBUG_WARNING("Ignoring incoming connection on active side\n");
    }
}

static void dtls_start_handshake(struct agent_t* const agent, struct sa* const peer) {
    if (!agent->offerer && agent->dtls_connection == NULL) {
        // Connect DTLS socket
        DEBUG_PRINTF("DTLS connect to %J\n", peer);
        EXIT_ON_ERROR(dtls_connect(&agent->dtls_connection, agent->dtls_context, agent->dtls_socket,
            peer, dtls_establish_handler, dtls_receive_handler, dtls_close_handler, agent));
        DEBUG_PRINTF("Verifying peer's certificate\n");
        EXIT_ON_ERROR(tls_peer_verify(agent->dtls_connection));
    }
}

static void remove_dtls_socket(struct agent_t* const agent) {
    if (agent->dtls_connection != NULL) {
        DEBUG_PRINTF("Removing DTLS connection\n");
        mem_deref(agent->dtls_connection);
        agent->dtls_connection = NULL;
    }
    if (agent->dtls_helper != NULL) {
        DEBUG_PRINTF("Removing DTLS send helper\n");
        mem_deref(agent->dtls_helper);
    }
    if (agent->dtls_socket != NULL) {
        DEBUG_PRINTF("Removing DTLS socket\n");
        mem_deref(agent->dtls_socket);
        agent->dtls_socket = NULL;
    }
}

static void dtls_attach_candidate(struct agent_t* const agent, struct udp_sock* const udp_socket, struct sa* const peer) {
    if (agent->dtls_socket == NULL) {
        // Create DTLS socket
        DEBUG_PRINTF("Creating DTLS socket\n");
        EXIT_ON_ERROR(dtls_listen(&agent->dtls_socket, NULL, udp_socket, 0,
            LAYER_DTLS, dtls_connect_handler, agent));
     
        // TODO: Add send helper to send on chosen candidate's UDP socket
        
        // Do DTLS handshake
        dtls_start_handshake(agent, peer);
    } else {
        // Attach to DTLS socket
        DEBUG_PRINTF("Attaching to DTLS socket\n");
        EXIT_ON_ERROR(dtls_attach_udp_sock(agent->dtls_socket, udp_socket, LAYER_DTLS));
    }
}

static void clear_selected_candidate_pair(struct agent_t* const agent) {
    if (agent->selected_pair != NULL) {
        // Remove current pair
        DEBUG_PRINTF("Removing selected candidate pair: %H\n", trice_candpair_debug, agent->selected_pair);
        mem_deref(agent->selected_pair);
        agent->selected_pair = NULL;
    }
}

static void set_selected_candidate_pair(struct agent_t* const agent, struct ice_candpair* const candidate_pair) {
    // Clear
    clear_selected_candidate_pair(agent);
    
    // Set new
    agent->selected_pair = mem_ref(candidate_pair);
    DEBUG_PRINTF("Selecting candidate pair: %H\n", trice_candpair_debug, agent->selected_pair);
}

static void ice_completed_handler(struct agent_t* const agent) {
    // Debug
    DEBUG_INFO("Checklist completed!\n");
    EXIT_ON_ERROR(trice_debug(&print_handler, agent->ice));
    
    // Select candidate pair
    // TODO: Is it ordered by priority?
    struct list const* const candidate_pairs = trice_validl(agent->ice);
    EXIT_ON_NULL(candidate_pairs);
    struct le const* const element = list_head(candidate_pairs);
    EXIT_ON_NULL(element);
    struct ice_candpair* const candidate_pair = element->data;
    EXIT_ON_NULL(candidate_pair);
    set_selected_candidate_pair(agent, candidate_pair);
    
    // Add DTLS send helper: Send data to the selected candidate
    if (agent->dtls_helper == NULL) {
        DEBUG_PRINTF("Adding DTLS send helper\n");
        struct udp_sock* const udp_socket = dtls_udp_sock(agent->dtls_socket);
        EXIT_ON_ERROR(udp_register_helper(&agent->dtls_helper, udp_socket, LAYER_REDIRECT,
            dtls_send_helper, NULL, agent));
    }
}

static void udp_error_handler(int const err, void* const arg) {
    (void)(arg);
    DEBUG_WARNING("udp_error_handler(err: %m)\n", err);
    EXIT_ON_ERROR(err);
}

static void ice_established_handler(struct ice_candpair* const candidate_pair, struct stun_msg const* const message, void* const arg) {
    struct agent_t* const agent = arg;
    DEBUG_PRINTF("Candidate pair established: %H\n", trice_candpair_debug, candidate_pair);
    
    // Set UDP error handler
    struct udp_sock* const udp_socket = trice_lcand_sock(agent->ice, candidate_pair->lcand);
    udp_error_handler_set(udp_socket, udp_error_handler);
    
    // Attach to DTLS socket
    struct sa* const peer = &candidate_pair->lcand->attr.addr;
    dtls_attach_candidate(agent, udp_socket, peer);
    
    // Completed all candidate pairs?
    if (trice_checklist_iscompleted(agent->ice)) {
        ice_completed_handler(agent);
    }
}

static void ice_failed_handler(int err, uint16_t scode, struct ice_candpair* const candidate_pair, void* const arg) {
    struct agent_t* const agent = arg;
    DEBUG_PRINTF("Candidate pair failed: %H (%m %"PRIu16")\n", trice_candpair_debug, candidate_pair, err, scode);
    
    // Completed all candidate pairs?
    if (trice_checklist_iscompleted(agent->ice)) {
        ice_completed_handler(agent);
    }
}

#define _SEPARATE '\n'

static void info_out(struct agent_t const* const agent) {
    struct mbuf* const buffer = mbuf_alloc(1024);
    struct re_printf mbuf_handler = {
        .vph = _mbuf_handler,
        .arg = buffer
    };
    EXIT_ON_NULL(buffer);
    
    // Add username fragment
    EXIT_ON_ERROR(mbuf_write_str(buffer, agent->ufrag));
    EXIT_ON_ERROR(mbuf_write_u8(buffer, _SEPARATE));
    
    // Add password
    EXIT_ON_ERROR(mbuf_write_str(buffer, agent->pwd));
    EXIT_ON_ERROR(mbuf_write_u8(buffer, _SEPARATE));
    
    // Add certificate fingerprint
    uint8_t sha256_bytes[32];
    EXIT_ON_ERROR(tls_fingerprint(agent->dtls_context, TLS_FINGERPRINT_SHA256,
        sha256_bytes, sizeof(sha256_bytes)));
    size_t i;
    EXIT_ON_ERROR(mbuf_printf(buffer, "%02X", sha256_bytes[0]));
    for (i = 1; i < sizeof(sha256_bytes); ++i) {
        EXIT_ON_ERROR(mbuf_printf(buffer, ":%02X", sha256_bytes[i]));
    }
    EXIT_ON_ERROR(mbuf_write_u8(buffer, _SEPARATE));
    
    // Add candidates
    struct list const* const candidates = trice_lcandl(agent->ice);
    EXIT_ON_NULL(candidates);
    struct le const* element;
    LIST_FOREACH(candidates, element) {
		struct ice_lcand const* const candidate = element->data;
        EXIT_ON_NULL(candidate);
        EXIT_ON_ERROR(ice_cand_attr_encode(&mbuf_handler, &candidate->attr));
        EXIT_ON_ERROR(mbuf_write_u8(buffer, _SEPARATE));
    }
    
    // Print info
    char* info_string;
    mbuf_set_pos(buffer, 0);
    EXIT_ON_ERROR(mbuf_strdup(buffer, &info_string, buffer->end));
    DEBUG_INFO("Local Info (raw):\n%s----------\n", info_string);
    mem_deref(info_string);
    
    // Buffer to Base64
    size_t base64_len = buffer->end * 2;
    char base64_string[base64_len];
    EXIT_ON_ERROR(base64_encode(buffer->buf, buffer->end, base64_string, &base64_len));
    DEBUG_PRINTF("Local Info (base64):\n");
    printf("%.*s\n----------\n", (int) base64_len, base64_string);
    
    // Prompt
    DEBUG_INFO("Gimme Info (base64) from remote:\n");
    mem_deref(buffer);
}

static char* _get_next(struct mbuf* buffer) {
    size_t const start = buffer->pos;
    size_t pos = start;
    while (mbuf_get_left(buffer) > 0) {
        if (mbuf_read_u8(buffer) == (uint8_t) _SEPARATE) {
            char* line;
            size_t const left = mbuf_get_left(buffer);
            mbuf_set_pos(buffer, start);
            EXIT_ON_ERROR(mbuf_strdup(buffer, &line, pos - start));
            if (left > 0) {
                mbuf_set_pos(buffer, pos + 1);
            }
            if (strlen(line) == 0) {
                mem_deref(line);
                return NULL;
            }
            return line;
        }
        pos += 1;
    }
    return NULL;
}

static void info_in(struct agent_t* const agent, struct mbuf* const base64_buffer) {
    // Decode info into mbuf
    struct mbuf* buffer = mbuf_alloc(base64_buffer->size * 2);
    EXIT_ON_NULL(buffer);
    buffer->end = buffer->size;
    EXIT_ON_ERROR(base64_decode((char const*) base64_buffer->buf, base64_buffer->end,
        buffer->buf, &buffer->end));
    
    // Print info
    char* info_string;
    EXIT_ON_ERROR(mbuf_strdup(buffer, &info_string, buffer->end));
    DEBUG_INFO("Remote Info (raw):\n%s----------\n", info_string);
    mem_deref(info_string);
    mbuf_set_pos(buffer, 0);
    
    // Get username fragment
    char* ufrag = _get_next(buffer);
    EXIT_ON_NULL(ufrag);
    DEBUG_PRINTF("Setting remote 'ufrag': %s\n", ufrag);
    EXIT_ON_ERROR(trice_set_remote_ufrag(agent->ice, ufrag));
    mem_deref(ufrag);
    
    // Get password
    char* pwd = _get_next(buffer);
    EXIT_ON_NULL(pwd);
    DEBUG_PRINTF("Setting remote 'pwd': %s\n", pwd);
    EXIT_ON_ERROR(trice_set_remote_pwd(agent->ice, pwd));
    mem_deref(pwd);
    
    // Get certificate fingerprint
    char* fingerprint = _get_next(buffer);
    EXIT_ON_NULL(fingerprint);
    DEBUG_PRINTF("TODO: Should check remote fingerprint: %s\n", fingerprint);
    mem_deref(fingerprint);
    
    // Get candidates
    char* candidate;
    for (candidate = _get_next(buffer); candidate != NULL; candidate = _get_next(buffer)) {
        DEBUG_PRINTF("Adding remote 'candidate': %s\n", candidate);
        struct ice_cand_attr remote_candidate;
        EXIT_ON_ERROR(ice_cand_attr_decode(&remote_candidate, candidate));
        EXIT_ON_ERROR(trice_rcand_add(NULL, agent->ice, remote_candidate.compid,
            remote_candidate.foundation, remote_candidate.proto, remote_candidate.prio,
            &remote_candidate.addr, remote_candidate.type, remote_candidate.tcptype));
        mem_deref(candidate);
    }
    
    // Have remote
    agent->have_remote = true;
    
    // Run checklist
    if (!list_isempty(trice_rcandl(agent->ice)) && !trice_checklist_isrunning(agent->ice)) {
        DEBUG_PRINTF("Starting checklist with pacing interval %"PRIu32" ms\n", agent->pacing_interval);
        EXIT_ON_ERROR(trice_checklist_start(agent->ice, NULL, agent->pacing_interval, true,
            ice_established_handler, ice_failed_handler, agent));
    }
    
    mem_deref(buffer);
}

static void stop(struct agent_t* const agent) {
    // Cleanup
    clear_selected_candidate_pair(agent);
    remove_dtls_socket(agent);
    mem_deref(agent->dtls_context);
    mem_deref(agent->ice);
    fd_close(STDIN_FILENO);
    mem_deref(agent->redirect_buffer);
    fd_close(agent->redirect_socket);
    close(agent->redirect_socket);
    
    // Bye
    before_exit();
    exit(0);
}

static void stdin_handler(int flags, void* const arg) {
    struct agent_t* const agent = arg;
    
    // Get message from stdin
    struct mbuf* const buffer = mbuf_alloc(1024);
    EXIT_ON_NULL(buffer);
    EXIT_ON_NULL(fgets((void*) buffer->buf, 1024, stdin));
    buffer->end = strlen((char*) buffer->buf);
    
    // Exit?
    if (mbuf_get_left(buffer) == 1 && *mbuf_buf(buffer) == '\n') {
        mem_deref(buffer);
        stop(agent);
    }
    
    // Have remote?
    if (!agent->have_remote) {
        // Decode ufrag, pwd and candidates from base64
        info_in(agent, buffer);
        mem_deref(buffer);
        return;
    }
    
    // Send data
    DEBUG_PRINTF("Selected candidate pair: %H\n", trice_candpair_debug, agent->selected_pair);
    if (agent->selected_pair == NULL) {
        DEBUG_WARNING("Cannot send data, no selected candidate pair, yet!\n");
    } else {
        DEBUG_INFO("Sending %zu bytes via DTLS connection\n", mbuf_get_left(buffer));
        int error = dtls_send(agent->dtls_connection, buffer);
        if (error) {
            DEBUG_WARNING("Could not send, error: %m\n", error);
        }
    }
    
    mem_deref(buffer);
}

static void signal_handler(int sig) {
	DEBUG_INFO("Got signal: %d, terminating...\n", sig);
	before_exit();
    exit(0);
}

int main(int argc, char* argv[argc + 1]) {
    struct agent_t agent = {0};
    // Offerer?
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <0|1 (offerer)> <redirect-ip>", argv[0]);
        return 1;
    }
    
    // Initialise
    EXIT_ON_ERROR(libre_init());
    
    // Debug
    dbg_init(DBG_DEBUG, DBG_ALL);
    DEBUG_PRINTF("Init\n");
    
    // Create agent
    agent.offerer = argv[1][0] == '1';
    agent.config = default_config;
    rand_str(agent.ufrag, sizeof(agent.ufrag));
    rand_str(agent.pwd, sizeof(agent.pwd));
    EXIT_ON_ERROR(trice_alloc(&agent.ice, &agent.config, agent.offerer,
        agent.ufrag, agent.pwd));
    agent.pacing_interval = 20;
    agent.have_remote = false;
    agent.selected_pair = NULL;
    agent.packet_counter = 0;
    agent.wireshark_hex = fopen("trace_in.hex", "w");
    EXIT_ON_NULL(agent.wireshark_hex);
    
    // Create DTLS context
    EXIT_ON_ERROR(tls_alloc(&agent.dtls_context, TLS_METHOD_DTLS, NULL, NULL));
    EXIT_ON_ERROR(tls_set_selfsigned(agent.dtls_context, "test"));
    tls_set_verify_client(agent.dtls_context);
    agent.dtls_socket = NULL;
    agent.dtls_connection = NULL;
    agent.dtls_helper = NULL;
    
    // Create redirect raw socket
    EXIT_ON_ERROR(sa_set_str(&agent.redirect_address, argv[2], 0));
    agent.redirect_socket = socket(AF_INET, SOCK_RAW, IPPROTO_SCTP);
    if (agent.redirect_socket == -1) {
        EXIT_ON_ERROR(errno);
    }
    EXIT_ON_ERROR(fd_listen(agent.redirect_socket, FD_READ, redirect_from_machine, &agent));
    agent.redirect_buffer = mbuf_alloc(65536);
    EXIT_ON_NULL(agent.redirect_buffer);
    
    // Start gathering
    net_if_apply(interface_handler, &agent);
    // Note: Gathering is done at this point
    
    // Listen on stdin
    EXIT_ON_ERROR(fd_listen(STDIN_FILENO, FD_READ, stdin_handler, &agent));
    
    // Debug
    DEBUG_PRINTF("Best polling method: %s\n", poll_method_name(poll_method_best()));
    EXIT_ON_ERROR(trice_debug(&print_handler, agent.ice));
    
    // Output: ufrag, pwd and candidates as base64
    info_out(&agent);
    
    // Start main loop
    EXIT_ON_ERROR(re_main(signal_handler));
    DEBUG_WARNING("BEYOND MAIN, PANIC PANIC!");
    return 0;
}
