/******************************************************************************
* Copyright (c) 2000-2018 Ericsson Telecom AB
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
//  Description:        SunRPC test port header
//  Rev:                R5B
//  Prodnr:             CNL 113 493
//


#ifndef SunRPCmsg__PT_HH
#define SunRPCmsg__PT_HH

#include "SunRPCasp_PortType.hh"
#include "Abstract_Socket.hh"

namespace SunRPCasp__PortType {

#ifdef AS_USE_SSL
  class SunRPCasp__PT : public SSL_Socket, public SunRPCasp__PT_BASE {
#else
  class SunRPCasp__PT : public Abstract_Socket, public SunRPCasp__PT_BASE {
#endif
  public:
    SunRPCasp__PT(const char *par_port_name=NULL);
    ~SunRPCasp__PT();

    void set_parameter(const char *parameter_name, const char *parameter_value);

  protected:
    void user_map(const char *system_port);
    void user_unmap(const char *system_port);

    void user_start();
    void user_stop();

    const char* local_port_name();
    const char* remote_address_name();
    const char* local_address_name();
    const char* remote_port_name();
    const char* halt_on_connection_reset_name();
    const char* server_mode_name();
    const char* socket_debugging_name();
    const char* nagling_name();
    const char* server_backlog_name();
    const char* ssl_use_ssl_name();
    const char* ssl_use_session_resumption_name();
    const char* ssl_private_key_file_name();
    const char* ssl_trustedCAlist_file_name();
    const char* ssl_certificate_file_name();
    const char* ssl_password_name();
    const char* ssl_cipher_list_name();
    const char* ssl_verifycertificate_name();

    void outgoing_send(const SunRPCasp__Types::ASP__SunRPC__Connect& send_par);
    void outgoing_send(const SunRPCasp__Types::ASP__SunRPC__Close& send_par);
    void outgoing_send(const SunRPCasp__Types::ASP__SunRPC__Listen& send_par);
    void outgoing_send(const SunRPCasp__Types::ASP__SunRPC__Shutdown& send_par);

    void listen_port_opened(int port_number);
    void client_connection_opened(int client_id);
    void peer_connected(int client_id, sockaddr_in& addr);
    void peer_disconnected(int client_id);
    void Add_Fd_Read_Handler(int fd) { Handler_Add_Fd_Read(fd); }
    void Add_Fd_Write_Handler(int fd) { Handler_Add_Fd_Write(fd); }
    void Remove_Fd_Read_Handler(int fd) { Handler_Remove_Fd_Read(fd); }
    void Remove_Fd_Write_Handler(int fd) { Handler_Remove_Fd_Write(fd); }
    void Remove_Fd_All_Handlers(int fd) { Handler_Remove_Fd(fd); }
    void Handler_Uninstall() { Uninstall_Handler(); }
    void Timer_Set_Handler(double call_interval, boolean is_timeout = TRUE,
      boolean call_anyway = TRUE, boolean is_periodic = TRUE) {
      Handler_Set_Timer(call_interval, is_timeout, call_anyway, is_periodic);
    }
	
    // SunRPC port specific functions
    void outgoing_send(const SunRPCasp__Types::SunRPC__message& send_par);
    void outgoing_send(const SunRPCasp__Types::SunRPC__message__multiple__client& send_par);
    void message_incoming(const unsigned char* msg, int length, int client_id = -1);
    
  private:
    void Handle_Fd_Event(int fd, boolean is_readable, boolean is_writable, boolean is_error);
    void Handle_Timeout(double time_since_last_call);

    void outgoing_send(const SunRPCasp__Types::SunRPC__message& send_par, int client_id);
  };

}//namespace

#endif
