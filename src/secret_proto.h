/**
 * @file secret_proto.h
 * @author Peter Zdravecký (xzdrav00)
 * @version 0.1
 * @date 2021-11-07
 *
 * @copyright Copyright (c) 2021
 *
 */
#pragma once

enum pkt_type { HEAD, DATA, END }; /* Defines packet type */

struct secret_proto {
    char proto_name[4] = "MNT"; /* Protocl name */
    int type;                   /* Defines packet type */
    int datalen;                /* The length of the data being sent */
    int seq;                    /* Sequence number of the packet */
    int client_id;              /* Idetification number of client */
};
