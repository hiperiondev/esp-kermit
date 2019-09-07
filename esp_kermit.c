/*
 * This file is part of the esp-iot-secure-core distribution (https://github.com/hiperiondev/esp-iot-secure-core).
 * Copyright (c) 2019 Emiliano Augusto Gonzalez (comercial@hiperion.com.ar)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#define NODBUG
#define STATIC static

#include "ekermit/debug.h"
#include "ekermit/kermit.h"

int readpkt(struct k_data *, unsigned char *, int);
int tx_data(struct k_data *, unsigned char *, int);
int inchk(struct k_data *);

int openfile(struct k_data *, unsigned char *, int);
int writefile(struct k_data *, unsigned char *, int);
int readfile(struct k_data *);
int closefile(struct k_data *, unsigned char, int);
unsigned long fileinfo(struct k_data *, unsigned char *, unsigned char *, int, short *, short);

// External data
extern unsigned char o_buf[];
extern unsigned char i_buf[];

struct k_data     k_data;
struct k_response k_response;

int esp_kermit_init(short xfermode, short remote, short binary, short parity, short bct, short ikeep, unsigned char ** filelist) {
    int status;

    k_data.xfermode = xfermode;                 // Text/binary automatic/manual
    k_data.remote   = remote;                   // Remote vs local
    k_data.binary   = binary;                   // 0 = text, 1 = binary
    k_data.parity   = parity;                   // Communications parity
    k_data.bct      = (bct == 5) ? 3 : bct;     // Block check type
    k_data.ikeep    = ikeep;                    // Keep incompletely received files
    k_data.filelist = filelist;                 // List of files to send (if any)
    k_data.cancel   = 0;                        // Not canceled yet

    k_data.zinbuf   = i_buf;                    // File input buffer
    k_data.zinlen   = IBUFLEN;                  // File input buffer length
    k_data.zincnt   = 0;                        // File input buffer position
    k_data.obuf     = o_buf;                    // File output buffer
    k_data.obuflen  = OBUFLEN;                  // File output buffer length
    k_data.obufpos  = 0;                        // File output buffer position

    k_data.rxd      = readpkt;                  // for reading packets
    k_data.txd      = tx_data;                  // for sending packets
    k_data.ixd      = inchk;                    // for checking connection
    k_data.openf    = openfile;                 // for opening files
    k_data.finfo    = fileinfo;                 // for getting file info
    k_data.readf    = readfile;                 // for reading files
    k_data.writef   = writefile;                // for writing to output file
    k_data.closef   = closefile;                // for closing files
#ifdef DEBUG
    k_data.dbf      = 0;                        // for debugging
#else
    k_data.dbf      = 0;
#endif
    k_data.bctf     = (bct == 5) ? 1 : 0;       // Force Type 3 Block Check (16-bit CRC) on all packets, or not

    status = kermit(K_INIT, &k_data, 0, 0, "", &k_response);
#ifdef DEBUG
    debug(DB_LOG, "init status:", 0, status);
    debug(DB_LOG, "version:", k_data.version, 0);
#endif

    return status;
}
