// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (C) 2012-2016, Ryan P. Wilson
//
//      Authority FX, Inc.
//      www.authorityfx.com

#include "licensechecker.h"

#include <ipp.h>
#include <ippcp.h>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <iomanip>
#include <cstring> //for memcpy
#include <cstdlib> //strtoul
#include <string>

#include "get_mac.h"

Plugin::Plugin(std::string name, LicenseType type, int count, bool floating) {
  SetName(name);
  SetType(type);
  SetCount(count);
  SetFloating(floating);
}
void Plugin::SetName(std::string name) {
  name_ = name;
}
void Plugin::SetType(LicenseType type) {
  type_ = type;
}
void Plugin::SetCount(int count) {
  count_ = count;
}
void Plugin::SetFloating(bool floating) {
  floating_ = floating;
}
std::string Plugin::GetName() const {
  return name_;
}
LicenseType Plugin::GetType() const {
  return type_;
}
int Plugin::GetCount() const {
  return count_;
}
bool Plugin::GetFloating() const {
  return floating_;
}

LicenseResult LicenseChecker::DecryptLicense() {
  std::string license_str;
  try
  {
    //std::string dir = getModuleDirectory();
    std::string dir = std::getenv("AFX_PATH");
    std::string file_path = dir + "/license/afx-license.dat";

    std::ifstream license_file;
    //Open conf file
    license_file.open(file_path.c_str(), std::ifstream::in);

    if (license_file.is_open()) {
      //Read file
      char raw[500];
      license_file.get(raw, 500);
      license_str = raw;
      license_file.close();
    } else {
      return LR_NO_FILE;
    }
  } catch(std::exception e) { return LR_ERROR; }

  //convert to lowercase
  std::transform(license_str.begin(), license_str.end(), license_str.begin(), ::tolower);
  //remove whitespace
  std::remove_if(license_str.begin(), license_str.end(), ::isspace);

  int license_size = ((int)license_str.size() / 2) - 20;

  const int blkSize = 16;
  int ctxSize;
  ippsRijndael128GetSize(&ctxSize);

  // allocate memory for Rijndael context
  IppsRijndael128Spec* ctx = (IppsRijndael128Spec*)( new Ipp8u [ctxSize] );

  // 256-bit key
  Ipp8u key[32] = {
    0xc3,0x78,0x09,0x9a,0x15,0xd1,0xae,0x28,
    0xf0,0xa3,0x32,0x80,0x82,0xe4,0xa9,0x43,
    0x47,0xe0,0xa7,0xf5,0xbb,0xf9,0x02,0xe5,
    0xc8,0xc3,0x2a,0xf5,0x6d,0x56,0x73,0xad
  };

  // counter
  Ipp8u ctr0[blkSize] = {
    0x29,0xe3,0x65,0x6c,0xe4,0xee,0x02,0x92,
    0x8c,0x3d,0x22,0xa4,0x5e,0xbf,0xdb,0x64
  };

  // Rijndael context initialization
  ippsRijndael128Init(key, IppsRijndaelKey256, ctx);

  Ipp8u ctr[blkSize];
  memcpy(ctr, ctr0, sizeof(ctr0));

  Ipp8u* ciph = new Ipp8u[license_size];
  Ipp8u* deciph = new Ipp8u[license_size];
  Ipp8u hash_file[20];

  //Extract ciph
  for (int i = 0; i < license_size * 2; i+=2) {
    std::stringstream temp;
    temp << "0x" << std::setw(2) << std::setfill('0') << std::hex << license_str.substr(i, 2);
    ciph[i/2] = (Ipp8u)strtoul(temp.str().c_str(), NULL, 0);
  }

  std::string hash_str;
  hash_str = license_str.substr(license_size*2, 40);

  //Extract hash digest
  for (int i = 0; i < 40; i+=2) {
    std::stringstream temp;
    temp << "0x" << std::setw(2) << std::setfill('0') << std::hex << hash_str.substr(i, 2);
    hash_file[i/2] = (Ipp8u)strtoul(temp.str().c_str(), NULL, 0);
  }

  ippsRijndael128DecryptCTR(ciph, deciph, license_size, ctx, ctr, 64);

  //hash deciph
  Ipp8u hash[20];
  ippsSHA1MessageDigest(deciph, license_size, hash);

  // TODO create a wrapper class for encyption to handle heap memory
  //Check hash
  for (int i = 0; i < 20; i++) {
    if (hash[i] == hash_file[i]) {
      continue;
    } else {
      delete[] ciph;
      delete[] deciph;
      ciph = 0;
      deciph = 0;
      return LR_ERROR;
    }
  }

  std::stringstream deciph_ss;
  for (int i = 0; i < license_size; i++) {
    deciph_ss << deciph[i];
  }

  delete[] ciph;
  delete[] deciph;

  int parse_result = ParseLicense_(deciph_ss.str());

  //Check parse result
  if (parse_result == 0) {
    return LR_GOOD;
  } else {
    return LR_ERROR;
  }
}

int LicenseChecker::ParseLicense_(std::string license) {
  size_t start;
  size_t end;

  //convert to lowercase
  std::transform(license.begin(), license.end(), license.begin(), ::tolower);
  //remove whitespace
  std::remove_if(license.begin(), license.end(), ::isspace);

  //Num of plugins
  start = license.find("num_plugs={") + 11;
  end = license.find_first_of("}", start) - 1;

  int num_plugs;

  try {
    std::stringstream ss(license.substr(start, end));
    ss >> num_plugs;
    if (num_plugs < 1) { return 1; }
  } catch(std::exception e) { return 1; }

  //Find plugins
  start = license.find("plugins={") + 9;
  end = license.find_first_of("}", start) - 1;

  std::string plugins = license.substr(start, end - start + 1);

  start = 0;

  for (int i = 0; i < num_plugs; i++) {
    std::string name;
    int type;
    int count;
    int floating;

    //Find name
    end = plugins.find_first_of("[", start) - 1;
    name = plugins.substr(start, end - start + 1);
    if (name.length() < 1) { return 1; }

    //Find type
    start = end + 2;
    end = plugins.find_first_of(",", start) - 1;
    try {
      std::stringstream ss(plugins.substr(start, end - start + 1));
      ss >> type;
    } catch(std::exception e) { return 1; }

    //Find count
    start = end + 2;
    end = plugins.find_first_of(",", start) - 1;
    try {
      std::stringstream ss(plugins.substr(start, end - start + 1));
      ss >> count;
    } catch(std::exception e) { return 1; }

    //Find floating
    start = end + 2;
    end = plugins.find_first_of("]", start) - 1;
    try {
      std::stringstream ss(plugins.substr(start, end - start + 1));
      ss >> floating;
    } catch(std::exception e) { return 1; }

    //add plugin to license
    Plugin temp(name, (LicenseType)type, count, floating == 1 ? true : false);
    plugins_list_.push_back(temp);

    start = end + 2;
  }

  //Find mac address
  start = license.find("uuid1={") + 7;
  end = license.find_first_of("}", start) - start;

  std::string uuid1 = license.substr(start, end);
  if (uuid1.length() < 1) { return 1; }

  uuid1_ = uuid1;

  //Find hdd uuid
  start = license.find("uuid2={") + 7;
  end = license.find_first_of("}", start) - start;

  std::string uuid2 = license.substr(start, end);
  if (uuid2.length() < 1) { return 1; }

  uuid2_ = uuid2;

  return 0;
}

LicenseResult LicenseChecker::CheckLicense(std::string name, LicenseType type) {
  bool licensed = false;

  //Check uuid1 MAC address
  if (hasMacAddress(uuid1_) == 0) {
    for (std::list<Plugin>::iterator it = plugins_list_.begin(); it != plugins_list_.end(); ++it) {
      if (it->GetName() == name) {
        //if license types are the same
        if(it->GetType() == type) {
          licensed = true;
          break;
        }
        //if running a workstation version
        else if(it->GetType() == L_WORKSTATION && type == L_RENDER) {
          licensed = true;
          break;
        }
      }
    }
    if (licensed == true) {
      return LR_GOOD;
    } else {
      return LR_NOT_LICENSED;
    }
  } else {
    return LR_CHECK_UUID1;
  }
}




