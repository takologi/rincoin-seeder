// Copyright (c) 2024-2026 The Rincoin community developers
// Originally derived from bitcoin-seeder by Pieter Wuille (sipa).
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#ifndef _RINCOIN_H_
#define _RINCOIN_H_ 1

#include "protocol.h"

bool TestNode(const CService &cip, int &ban, int &client, std::string &clientSV, int &blocks, std::vector<CAddress>* vAddr, uint64_t& services);

#endif // _RINCOIN_H_
