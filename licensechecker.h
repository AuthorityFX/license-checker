// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (C) 2012-2016, Ryan P. Wilson
//
//      Authority FX, Inc.
//      www.authorityfx.com

#ifndef LICENSECHECKER_H_
#define LICENSECHECKER_H_

#include <iostream>
#include <list>

enum LicenseResult {
  LR_GOOD         =  0,
  LR_NOT_LICENSED = -1,
  LR_NO_FILE      = -2,
  LR_CHECK_UUID1  = -3,
  LR_CHECK_UUID2  = -4,
  LR_ERROR        = -5,
};

enum LicenseType {
  L_WORKSTATION,
  L_RENDER,
  L_TRIAL
};

class Plugin {
private:
    std::string name_;
    LicenseType type_;
    int count_;
    bool floating_;
public:
    Plugin() {};
    Plugin(std::string name, LicenseType type, int count, bool floating);

    void SetName(std::string name);
    void SetType(LicenseType type);
    void SetCount(int count);
    void SetFloating(bool floating);

    std::string GetName() const;
    LicenseType GetType() const;
    int GetCount() const;
    bool GetFloating() const;
};

class LicenseChecker {
private:
    std::list<Plugin> plugins_list_;
    std::string uuid1_;
    std::string uuid2_;
    int ParseLicense_(std::string license);
public:
    LicenseChecker();
    LicenseResult DecryptLicense();
    LicenseResult CheckLicense(std::string name, LicenseType type);
};

#endif // LICENSECHECKER_H_
