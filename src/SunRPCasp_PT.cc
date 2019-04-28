/******************************************************************************
* Copyright (c) 2000-2019 Ericsson Telecom AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v2.0
* which accompanies this distribution, and is available at
* https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
*
* Contributors:
* Eduard Czimbalmos
* Attila Balasko
* Csaba Feher
* Gabor Szalai
* Kulcsár Endre
******************************************************************************/
//
//  File:               SunRPCasp_PT.cc
//  Description:        SunRPC test port source
//  Rev:                R5B
//  Prodnr:             CNL 113 493
//

#include "SunRPCasp_PT.hh"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace SunRPCasp__PortType {

using namespace SunRPCasp__Types;

SunRPCasp__PT::SunRPCasp__PT(const char *par_port_name)
#ifdef AS_USE_SSL
  : SSL_Socket("SunRPC", par_port_name)
#else
    : Abstract_Socket("SunRPC", par_port_name)
#endif        
    , SunRPCasp__PT_BASE(par_port_name)
{
  parameter_set(use_connection_ASPs_name(), "yes");
  set_ttcn_buffer_usercontrol(true);
}

SunRPCasp__PT::~SunRPCasp__PT()
{
}

void SunRPCasp__PT::set_parameter(const char *parameter_name,
                               const char *parameter_value)
{
  log_debug("entering SunRPCasp__PT::set_parameter(%s, %s)", parameter_name, parameter_value);

  if(!parameter_set(parameter_name ,parameter_value))
      TTCN_warning("SunRPCasp__PT::set_parameter(): Unsupported Test Port parameter: %s", parameter_name);

  log_debug("leaving SunRPCasp__PT::set_parameter(%s, %s)", parameter_name, parameter_value);
}

void SunRPCasp__PT::Handle_Fd_Event(int fd,
  boolean is_readable, boolean is_writable, boolean is_error)
{
  log_debug("entering SunRPCasp__PT::Handle_Fd_Event()");
  Handle_Socket_Event(fd, is_readable, is_writable, is_error);
  log_debug("leaving SunRPCasp__PT::Handle_Fd_Event()");
}

void SunRPCasp__PT::Handle_Timeout(double time_since_last_call)
{
  log_debug("entering SunRPCasp__PT::Handle_Timeout()");
  Handle_Timeout_Event(time_since_last_call);
  log_debug("leaving SunRPCasp__PT::Handle_Timeout()");
}

void SunRPCasp__PT::outgoing_send(const SunRPCasp__Types::SunRPC__message& send_par)
{
  log_debug("entering SunRPCmsg__PT::outgoing_send(SunRPC__message)");

  outgoing_send(send_par, -1);

  log_debug("leaving SunRPCmsg__PT::outgoing_send(SunRPC__message)");
}

void SunRPCasp__PT::outgoing_send(const SunRPCasp__Types::SunRPC__message__multiple__client& send_par)
{
  log_debug("entering SunRPCmsg__PT::outgoing_send(SunRPC__message__multiple__client)");

  if(send_par.client__id().ispresent())
    outgoing_send(send_par.rpc__msg(), send_par.client__id()());
  else
    outgoing_send(send_par.rpc__msg(), -1);

  log_debug("leaving SunRPCmsg__PT::outgoing_send(SunRPC__message__multiple__client)");
}

void SunRPCasp__PT::outgoing_send(const SunRPCasp__Types::SunRPC__message& send_par, int client_id)
{
  TTCN_Buffer fragment;
  fragment.clear();
  send_par.encode(SunRPC__message_descr_, fragment, TTCN_EncDec::CT_RAW);

  unsigned int first_four_bytes = fragment.get_len();
  // put an 1 into the first bit
  first_four_bytes |= (1 << 31);
  unsigned char first_four_chars[4];

  //for(unsigned int i = 0; i < 4; i++)
  //  first_four_chars[i] = first_four_bytes >> (8 * (4 - i - 1));
  
  // The same with less arithmetical operations:
  first_four_chars[0] = first_four_bytes >> 24;
  first_four_chars[1] = first_four_bytes >> 16;
  first_four_chars[2] = first_four_bytes >> 8;
  first_four_chars[3] = first_four_bytes;
  
  OCTETSTRING data(4, first_four_chars);
  data = data + OCTETSTRING(fragment.get_len(), fragment.get_data());

  if(client_id < 0)
    send_outgoing((const unsigned char*)data, data.lengthof());
  else
    send_outgoing((const unsigned char*)data, data.lengthof(), client_id);
}

void SunRPCasp__PT::message_incoming(const unsigned char* msg, int messageLength, int client_id)
{
  log_debug("entering SunRPCmsg__PT::message_incoming()");

  TTCN_Buffer msg_buf;
  msg_buf.clear();
  SunRPC__message rpc_msg;

  TTCN_Buffer* buf_p = get_buffer(client_id);
  buf_p->rewind();

  bool last_fragment = 0;
  // at least 4 bytes are needed in the buffer
  while(buf_p->get_read_len() > 3)
  {
    log_debug("SunRPCasp__PT::message_incoming(): decoding next message, buffer len: %d", buf_p->get_read_len());
    
    const unsigned char* msg_p = buf_p->get_read_data();
    unsigned int msg_length = 0;
    
    last_fragment = msg_p[0] & (1 << 7);
    log_debug("last_fragment: %s", last_fragment ? "yes" : "no");
    
    //for(unsigned int i = 0; i < 4; i++)
    //  msg_length += msg_p[i] << (8 * (4 - i - 1));

    //msg_length &= 0x7FFFFFFF;
    //log_debug("fragment size: %d", msg_length);

    // The same with less arithmetical operations:
    msg_length += (msg_p[0] << 24) & 0x7FFFFFFF;
    msg_length += msg_p[1] << 16;
    msg_length += msg_p[2] << 8;
    msg_length += msg_p[3];
    log_debug("fragment size: %d", msg_length);

    buf_p->set_pos(buf_p->get_pos() + 4);
    
    if(buf_p->get_read_len() >= msg_length)
    {
      msg_buf.put_os(OCTETSTRING(msg_length, buf_p->get_read_data()));
      buf_p->set_pos(buf_p->get_pos() + msg_length);

      if(last_fragment)
      {    
        log_hex("Buffer to be decoded: ", msg_buf.get_read_data(), msg_buf.get_read_len());
        rpc_msg.decode(SunRPC__message_descr_, msg_buf, TTCN_EncDec::CT_RAW);
        msg_buf.clear();
        buf_p->cut();
        buf_p->rewind();

        if(peer_list_get_nr_of_peers() == 1)
          incoming_message(rpc_msg);
        else
        {
          SunRPC__message__multiple__client msg_multiple;
          msg_multiple.client__id() = client_id;
          msg_multiple.rpc__msg() = rpc_msg;
          incoming_message(msg_multiple);
        }
      }
      else
      {
        log_debug("Fragment is not the last fragment of the message, waiting for the next fragment...");
      }
    }
    else
    {
      log_debug("Fragment is not entirely received, waiting for more data...");
      // quit the loop
      break;
    }
  }

  log_debug("leaving SunRPCmsg__PT::message_incoming()");
}

void SunRPCasp__PT::peer_disconnected(int client_id) {
  log_debug("entering SunRPCasp__PT::peer_disconnected()");
  if(get_use_connection_ASPs())
  {
    ASP__SunRPC__Close asp;
    asp.client__id() = client_id;
    incoming_message(asp);
  }
  else Abstract_Socket::peer_disconnected(client_id);
  log_debug("leaving SunRPCasp__PT::peer_disconnected()");
}

void SunRPCasp__PT::user_map(const char *system_port)
{
  log_debug("entering SunRPCasp__PT::user_map()");
  if(TTCN_Logger::log_this_event(TTCN_DEBUG)) {
      if(!get_socket_debugging())
          log_warning("%s: to switch on SunRPC test port debugging, set the '*.%s.socket_debugging := \"yes\" in the port's parameters.", get_name(), get_name());
  }
  map_user();
  log_debug("leaving SunRPCasp__PT::user_map()");
}

void SunRPCasp__PT::user_unmap(const char *system_port)
{
  log_debug("entering SunRPCasp__PT::user_unmap()");
  unmap_user();
  log_debug("leaving SunRPCasp__PT::user_unmap()");
}

void SunRPCasp__PT::user_start()
{
  log_debug("entering SunRPCasp__PT::user_start()");
  log_debug("SunRPC version: R2B (2007.05.10@15:05)");
  log_debug("leaving SunRPCasp__PT::user_start()");
}

void SunRPCasp__PT::user_stop()
{
  log_debug("entering SunRPCasp__PT::user_stop()");
  log_debug("leaving SunRPCasp__PT::user_stop()");
}

void SunRPCasp__PT::outgoing_send(const ASP__SunRPC__Connect& send_par)
{
  log_debug("entering SunRPCasp__PT::outgoing_send(ASP__SunRPC__Connect)");
  
  sockaddr_in local_addr, remote_addr;
  get_host_id(send_par.hostname(), &remote_addr);
  remote_addr.sin_port = htons((unsigned int)(INTEGER)send_par.portnumber());
  if(send_par.local__hostname().ispresent())
    get_host_id(send_par.local__hostname()(), &local_addr);
  else if(get_local_host_name())
  {
    log_debug("using local host name configured in %s: %s", local_address_name(), get_local_host_name());
    get_host_id(get_local_host_name(), &local_addr);
  }
  else
  {
    log_debug("using 'localhost' as local host name");
    get_host_id("localhost", &local_addr);
  }

  if(send_par.local__portnumber().ispresent())
    local_addr.sin_port = htons(send_par.local__portnumber()());
  else if(get_local_port_number() != 0)
  {
    log_debug("using local port number configured in %s: %d", local_port_name(), get_local_port_number());
    local_addr.sin_port = htons(get_local_port_number());
  }
  else
  {
    log_debug("using ephemeral local port number");
    local_addr.sin_port = htons(0);
  }
  
  open_client_connection(remote_addr, local_addr);

  log_debug("leaving SunRPCasp__PT::outgoing_send(ASP__SunRPC__Connect)");
}

void SunRPCasp__PT::client_connection_opened(int client_id)
{
  log_debug("entering SunRPCasp__PT::client_connection_opened(%d)", client_id);
  
  if(get_use_connection_ASPs())
  {
    ASP__SunRPC__Connect__result asp;

    asp.client__id() = client_id;

    incoming_message(asp);
  }
  else Abstract_Socket::client_connection_opened(client_id);

  log_debug("leaving SunRPCasp__PT::client_connection_opened()");
}

void SunRPCasp__PT::peer_connected(int client_id, sockaddr_in& addr)
{
  log_debug("entering SunRPCasp__PT::peer_connected(%d)", client_id);
  
  if(get_use_connection_ASPs())
  {
    ASP__SunRPC__Connected asp;

    asp.hostname() = inet_ntoa(addr.sin_addr);
    asp.portnumber() = ntohs(addr.sin_port);
    asp.client__id() = client_id;

    incoming_message(asp);
  }
  else Abstract_Socket::peer_connected(client_id, addr);
  
  log_debug("leaving SunRPCasp__PT::peer_connected()");
}

void SunRPCasp__PT::outgoing_send(const ASP__SunRPC__Close& send_par)
{
  log_debug("entering SunRPCasp__PT::outgoing_send(ASP__SunRPC__Close)");

  if(send_par.client__id().ispresent())
    remove_client((int)send_par.client__id()());
  else
    remove_all_clients();
  
  log_debug("leaving SunRPCasp__PT::outgoing_send(ASP__SunRPC__Close)");
}

void SunRPCasp__PT::outgoing_send(const ASP__SunRPC__Listen& send_par)
{
  log_debug("entering SunRPCasp__PT::outgoing_send(ASP__SunRPC__Listen)");

  sockaddr_in addr;
  if(send_par.local__hostname().ispresent())
    get_host_id(send_par.local__hostname()(), &addr);
  else if(get_local_host_name())
  {
    log_debug("using local host name configured in %s: %s", local_address_name(), get_local_host_name());
    get_host_id(get_local_host_name(), &addr);
  }
  else
  {
    log_debug("using 'localhost' as local host name");
    get_host_id("localhost", &addr);
  }
    
  if(send_par.portnumber().ispresent())
    addr.sin_port = htons((unsigned int)send_par.portnumber()());
  else if(get_local_port_number() != 0)
  {
    log_debug("using local port number configured in %s: %d", local_port_name(), get_local_port_number());
    addr.sin_port = htons(get_local_port_number());
  }
  else
  {
    log_debug("using ephemeral local port number");
    addr.sin_port = htons(0);
  }
  
  open_listen_port(addr);
  
  log_debug("leaving SunRPCasp__PT::outgoing_send(ASP__SunRPC__Listen)");
}

void SunRPCasp__PT::listen_port_opened(int port_number)
{
  log_debug("entering SunRPCasp__PT::listen_port_opened(%d)", port_number);
  
  if(get_use_connection_ASPs())
  {
    ASP__SunRPC__Listen__result asp;
    asp.portnumber() = port_number;
    incoming_message(asp);
  }
  else Abstract_Socket::listen_port_opened(port_number);
  
  log_debug("leaving SunRPCasp__PT::listen_port_opened()");
}

void SunRPCasp__PT::outgoing_send(const ASP__SunRPC__Shutdown& send_par)
{
  log_debug("entering SunRPCasp__PT::outgoing_send(ASP__SunRPC__Shutdown)");

  close_listen_port();

  log_debug("leaving SunRPCasp__PT::outgoing_send(ASP__SunRPC__Shutdown)");
}

const char* SunRPCasp__PT::local_port_name()              { return ""/*serverPort*/;}
const char* SunRPCasp__PT::remote_address_name()          { return ""/*destIPAddr*/;}
const char* SunRPCasp__PT::local_address_name()           { return ""/*serverIPAddr*/;}
const char* SunRPCasp__PT::remote_port_name()             { return ""/*destPort*/;}
const char* SunRPCasp__PT::halt_on_connection_reset_name(){ return ""/*halt_on_connection_reset*/;}
const char* SunRPCasp__PT::server_mode_name()             { return ""/*server_mode*/;}
const char* SunRPCasp__PT::socket_debugging_name()        { return "socket_debugging";}
const char* SunRPCasp__PT::nagling_name()                 { return ""/*nagling*/;}
const char* SunRPCasp__PT::server_backlog_name()          { return ""/*server_backlog*/;}
const char* SunRPCasp__PT::ssl_use_ssl_name()                { return "ssl_use_ssl";}
const char* SunRPCasp__PT::ssl_use_session_resumption_name() { return "ssl_use_session_resumption";}
const char* SunRPCasp__PT::ssl_private_key_file_name()       { return "ssl_private_key_file";}
const char* SunRPCasp__PT::ssl_trustedCAlist_file_name()     { return "ssl_trustedCAlist_file";}
const char* SunRPCasp__PT::ssl_certificate_file_name()       { return "ssl_certificate_chain_file";}
const char* SunRPCasp__PT::ssl_password_name()               { return "ssl_private_key_password";}
const char* SunRPCasp__PT::ssl_cipher_list_name()            { return "ssl_allowed_ciphers_list";}
const char* SunRPCasp__PT::ssl_verifycertificate_name()      { return "ssl_verify_certificate";}

}//namespace
