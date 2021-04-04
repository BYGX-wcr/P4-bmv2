/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <linux/socket.h> 
#include <linux/types.h>
#include <linux/if_ether.h>
#include <netinet/in.h>

#include <pcap/pcap.h>
#include "bmi_interface.h"

typedef struct ac_rule {
  uint8_t valid;
  uint32_t ipv4_vals[IPV4_4B_NUM];
  uint32_t ipv4_masks[IPV4_4B_NUM];
} ac_rule_t;

typedef struct bmi_interface_s {
  /* Original members defined by P4 community*/
  pcap_t *pcap;
  int fd;
  pcap_dumper_t *pcap_input_dumper;
  pcap_dumper_t *pcap_output_dumper;

  /* New members added by WCR, UCLA CSD */
  ac_rule_t drop_rule;
  uint16_t control_port_index;
} bmi_interface_t;

static uint16_t port_base = 100819;
static uint16_t port_index = 0;

static void control_msg_proc(int sockfd, bmi_interface_t *bmi) {
  char buff[128];
	int n;
  bzero(buff, 128);

  // read the message from client and copy it in buffer 
  read(sockfd, buff, sizeof(buff));
  if (strncmp(buff, "set", 3)) {
    // set a drop rule

    int ptr = 4; // starting point for L3 section
    if (strncmp(buff + ptr, "ipv4", 4)) {
      ptr += 4;
      //extract IPv4 filtering criteria which consists of 5 val&&&masks strings
      for (int i = 0; i < 5; ++i) {
        ++ptr; // skip blank
        int val_start = ptr, mask_start = ptr;
        int val_end = 0, mask_end = 0;
        while (buff[ptr] != ' ' && ptr < 128) {
          if (buff[ptr - 1] == '&' && buff[ptr] != '&') mask_start = ptr;
          if (buff[ptr + 1] == '&' && buff[ptr] != '&') val_end = ptr;
          ++ptr;
        }
        mask_end = ptr - 1;
        
        if (ptr == 128 || mask_start == val_start) {
          printf("Recv a message in incorrect format: %s", buff);
        }

        char val[20];
        char mask[20];
        bzero(val, 20);
        bzero(mask, 20);

        strncpy(val, buff + val_start, (val_end - val_start) + 1);
        strncpy(mask, buff + mask_start, (mask_end - mask_start) + 1);
        uint32_t mask_bs = strtol(mask, NULL, 16); // bit string of mask
        uint32_t val_bs = strtol(val, NULL, 16) & mask_bs; // bit string of val
        bmi->drop_rule.ipv4_masks[i] = mask_bs;
        bmi->drop_rule.ipv4_vals[i] = val_bs;
      }
    }

    bmi->drop_rule.valid = 1;
  }
  else if (strncmp(buff, "unset", 3)) {
    // unset the drop rule
    bmi->drop_rule.valid = 0;
  }
}

static void* bmi_interface_control_thread(void *arg) {
  bmi_interface_t *bmi = (bmi_interface_t *) arg;
  int sockfd, connfd, len;
	struct sockaddr_in servaddr, cli; 

	// socket create and verification 
	sockfd = socket(AF_INET, SOCK_STREAM, 0); 
	if (sockfd == -1) { 
		printf("socket creation failed...\n"); 
		pthread_exit(0); 
	} 
	else
		printf("Socket successfully created..\n"); 
	bzero(&servaddr, sizeof(servaddr)); 

	// assign IP, PORT 
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
	servaddr.sin_port = htons(port_base + bmi->control_port_index);
  port_index++; 

	// Binding newly created socket to given IP and verification 
	if ((bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))) != 0) { 
		printf("Socket bind failed...\n"); 
		pthread_exit(0);
	} 

	// Now server is ready to listen and verification 
	if ((listen(sockfd, 5)) != 0) { 
		printf("Listen failed...\n"); 
		pthread_exit(0);
	} 
	len = sizeof(cli);

	// Accept the data packet from client and verification
  while (1) {
    connfd = accept(sockfd, (struct sockaddr*)&cli, &len); 
    if (connfd < 0) { 
      printf("Server acccept failed...\n"); 
      continue;
    }

    // Function for chatting between client and server 
    control_msg_proc(connfd, bmi); 
  }

	// After chatting close the socket 
	close(sockfd); 
}

int bmi_interface_create(bmi_interface_t **bmi, const char *device) {
  bmi_interface_t *bmi_ = malloc(sizeof(bmi_interface_t));

  if(!bmi_) return -1;

  bmi_->pcap_input_dumper = NULL;
  bmi_->pcap_output_dumper = NULL;

  char errbuf[PCAP_ERRBUF_SIZE];
  bmi_->pcap = pcap_create(device, errbuf);

  if(!bmi_->pcap) {
    free(bmi_);
    return -1;
  }

  if(pcap_set_promisc(bmi_->pcap, 1) != 0) {
    pcap_close(bmi_->pcap);
    free(bmi_);
    return -1;
  }

#ifdef WITH_PCAP_FIX
  if(pcap_set_timeout(bmi_->pcap, 1) != 0) {
    pcap_close(bmi_->pcap);
    free(bmi_);
    return -1;
  }

  if(pcap_set_immediate_mode(bmi_->pcap, 1) != 0) {
    pcap_close(bmi_->pcap);
    free(bmi_);
    return -1;
  }
#endif

  if (pcap_activate(bmi_->pcap) != 0) {
    pcap_close(bmi_->pcap);
    free(bmi_);
    return -1;
  }

  bmi_->fd = pcap_get_selectable_fd(bmi_->pcap);
  if(bmi_->fd < 0) {
    pcap_close(bmi_->pcap);
    free(bmi_);
    return -1;
  }

  /* Configure the control port */
  char* ptr = device;
  while (*ptr != '-') ptr++; // skip host name
  ptr += 3; // skip prefix "eth"
  bmi_->control_port_index = atoi(ptr);

  /* Set up the thread that run the control socket */
  pthread_t pt_id;
  if (pthread_create(&pt_id, NULL, &bmi_interface_control_thread, (void *)bmi_) != 0) {
    pcap_close(bmi_->pcap);
    printf("Cannot set up control thread!\n");
    free(bmi_);
    return -1;
  }

  *bmi = bmi_;
  return 0;
}

int bmi_interface_destroy(bmi_interface_t *bmi) {
  pcap_close(bmi->pcap);
  if(bmi->pcap_input_dumper) pcap_dump_close(bmi->pcap_input_dumper);
  if(bmi->pcap_output_dumper) pcap_dump_close(bmi->pcap_output_dumper);
  free(bmi);
  return 0;
}

int bmi_interface_add_dumper(bmi_interface_t *bmi, const char *filename, bmi_dumper_kind_t dumper_kind) {
  pcap_dumper_t* dumper = pcap_dump_open(bmi->pcap, filename);
  if (dumper == NULL)
    return -1;
  switch (dumper_kind)
  {
  case bmi_input_dumper:
    bmi->pcap_input_dumper = dumper;
    break;
  case bmi_output_dumper:
    bmi->pcap_output_dumper = dumper;
    break;
  default:
    return -1;
  }
  return 0;
}

int bmi_interface_send(bmi_interface_t *bmi, const char *data, int len) {
  if(bmi->pcap_output_dumper) {
    struct pcap_pkthdr pkt_header;
    memset(&pkt_header, 0, sizeof(pkt_header));
    gettimeofday(&pkt_header.ts, NULL);
    pkt_header.caplen = len;
    pkt_header.len = len;
    pcap_dump((unsigned char *) bmi->pcap_output_dumper, &pkt_header,
	      (unsigned char *) data);
    pcap_dump_flush(bmi->pcap_output_dumper);
  }
  return pcap_sendpacket(bmi->pcap, (unsigned char *) data, len);
}

/* Does not make a copy! */
int bmi_interface_recv(bmi_interface_t *bmi, const char **data) {
  struct pcap_pkthdr *pkt_header;
  const unsigned char *pkt_data;

  if(pcap_next_ex(bmi->pcap, &pkt_header, &pkt_data) != 1) {
    return -1;
  }

  if(pkt_header->caplen != pkt_header->len) {
    return -1;
  }

  if(bmi->pcap_input_dumper) {
    pcap_dump((unsigned char *) bmi->pcap_input_dumper, pkt_header, pkt_data);
    pcap_dump_flush(bmi->pcap_input_dumper);
  }

  if (bmi->drop_rule.valid) {
    // drop rule is valid, check the packet
    uint16_t ether_type = 0;
    strncpy((char *)&ether_type, pkt_data + (ETH_ALEN * 2), 2);
    ether_type = ntohs(ether_type);
    if (ether_type == ETH_P_IP) {
      // ipv4 packet
      const unsigned char *ipv4_hdr = pkt_data + (ETH_ALEN * 2) + 2;
      int drop_flag = 1;
      for (int i = 0; i < IPV4_4B_NUM; ++i) {
        // check each 4 bytes word in the ipv4 header
        uint32_t word = 0;
        strncpy((char *)&word, ipv4_hdr + i * 32, 32);
        word = ntohl(word) & bmi->drop_rule.ipv4_masks[i];
        if (word != bmi->drop_rule.ipv4_vals[i]) {
          // mismatch, disable the drop flag
          drop_flag = 0;
          break;
        }
      }

      if (drop_flag) {
        return 0;
      }
    }
  }

  *data = (const char *) pkt_data;

  return pkt_header->len;
}

int bmi_interface_recv_with_copy(bmi_interface_t *bmi, char *data, int max_len) {
  int rv;
  struct pcap_pkthdr *pkt_header;
  const unsigned char *pkt_data;

  if(pcap_next_ex(bmi->pcap, &pkt_header, &pkt_data) != 1) {
    return -1;
  }

  if(pkt_header->caplen != pkt_header->len) {
    return -1;
  }

  if(bmi->pcap_input_dumper) {
    pcap_dump((unsigned char *) bmi->pcap_input_dumper, pkt_header, pkt_data);
    pcap_dump_flush(bmi->pcap_input_dumper);
  }

  rv = (max_len < pkt_header->len) ? max_len : pkt_header->len;

  memcpy(data, pkt_data, rv);

  return rv;
}

int bmi_interface_get_fd(bmi_interface_t *bmi) {
  return bmi->fd;
}
