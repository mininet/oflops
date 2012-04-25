#ifndef OFLOPS_H
#define OFLOPS_H

/** \mainpage oflops 
 *
 * oflops (OpenFlow operations per second) is created to 
 * benchmark an OpenFlow switch.
 *
 * @author Rob Sherwood
 * @date September 2009
 *
 *
 * Read the README file for instructions on building, setting up, and running oflops.
 *
 * \section test_module Writing New Modules
 * Test modules are event driven.  To write a new test module, you need to create a shared library that defines the appropriate callbacks.
 * Most callbacks have reasonable defaults, so new test modules do not have to define all callbacks.
 *
 * The list of callbacks are documented in <a href="structtest__module.html">struct test_module</a> and 
 * the API exposed to the test module is available in test_module.h .
 *
 * <i>Channels</i> are a critical concept in oflops.  Channels a roughly equivalent to interfaces, and there are
 * both control and data channels.  
 *
 * \subsection control_channel Control Channel
 *  The control channel is a reference to the openflow tcp control connection.  Each oflops run should only have one control channel defined.
 *  Openflow message from the switch are sent to oflops via one of the of_event_* callbacks and control messages are sent to the switch
 *  via the <a href="test__module_8h.html#84e360ed0ef80457bfa72b64e6b3dbea">oflops_send_mesg()</a> function.
 * \subsection data_channel Data Channel(s)
 *  A data channel is a reference to a raw interface connected (directly or logically) to the switch.  
 *  Each oflops run can define zero or more data channels.  Data channels are used for sourcing and syncing 
 *  emulated user traffic. Oflops is notified of new packets on the data channel via the <a href="test__module_8h.html#84e360ed0ef80457bfa72b64e6b3dbea">handle_pcap_event()</a> callback, and typically send outgoing data messages <a href="test__module_8h.html#84e360ed0ef80457bfa72b64e6b3dbea">oflops_send_raw_mesg()</a> function.
 *
 * \section example_modules Example modules
 * <UL>
 * <LI> debug.c is used for debugging oflops </LI>
 * <LI> pktin.c is test the number of packet in that can be
 *      provided by a switch and the associated delay. </LI>
 * </UL>
 */


#include "context.h"
#include "test_module.h"

struct run_module_param {
  struct oflops_context *ctx;
  int ix_mod;  
};

#endif
