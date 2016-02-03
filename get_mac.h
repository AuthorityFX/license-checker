// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (C) 2012-2016, Ryan P. Wilson
//
//      Authority FX, Inc.
//      www.authorityfx.com

#ifndef GET_MAC_H_
#define GET_MAC_H_

int hasMacAddress(const std::string& mac);

#ifdef WINDOWS
#include <winsock2.h>
#include <iphlpapi.h>

int hasMacAddress(const std::string& mac) {
  ULONG bufferLength = 0;

  //After calling this funciton, the required length of the array will be in
  //bufferLength
  ULONG result = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &bufferLength);

  //Something went wrong. We're relying on result being
  //ERROR_BUFFER_OVERFLOW. return error.
  if (result != ERROR_BUFFER_OVERFLOW) return -1;

  //Allocate memopry for the adapter list.
  PIP_ADAPTER_ADDRESSES adapterAddresses = (PIP_ADAPTER_ADDRESSES) malloc(bufferLength);

  //Get adapter information and store in adapterAddresses array.
  result = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, adapterAddresses, &bufferLength);

  if (result != NO_ERROR) {
    free(adapterAddresses);
    return -1;
  }

  for (unsigned long int i = 0; i < bufferLength / sizeof(IP_ADAPTER_ADDRESSES); i++) {
    char addressString[17];
    bool doContinue = false;

    if ((adapterAddresses + i)->PhysicalAddressLength == 6) {
      BYTE* pa = (adapterAddresses + i)->PhysicalAddress;

      //Print the mac address to a string of lowercase hex bytes separated by
      //colons
      sprintf(addressString, "%02x:%02x:%02x:%02x:%02x:%02x", pa[0], pa[1], pa[2], pa[3], pa[4], pa[5]);

      for (int c = 0; c < 17; c++) {
        if (addressString[c] >= '0' && addressString[c] <= '9' && addressString[c] != (BYTE)tolower(mac.c_str()[c])) {
          doContinue = true;
        }
      }

      //If this mac address is not the one we're looking for,
      //skip to the next mac address
      if (doContinue) continue;

      //Otherwise, we've found the right mac address. Return OK
      free(adapterAddresses);
      return 0;
    }
  }

  //Correct mac address not found. Return error
  free(adapterAddresses);
  return -1;
}

#endif

#ifdef LINUX
#endif

#endif  // GET_MAC_H_