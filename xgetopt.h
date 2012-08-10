// XGetopt.h  Version 1.2
//
// Author:  Hans Dietrich
//          hdietrich2@hotmail.com
//
// This software is released into the public domain.
// You are free to use it in any way you like.
//
// This software is provided "as is" with no expressed
// or implied warranty.  I accept no liability for any
// damage or loss of business that this software may cause.
//
// http://www.codeproject.com/KB/cpp/xgetopt.aspx
//
///////////////////////////////////////////////////////////////////////////////

#ifndef XGETOPT_H
#define XGETOPT_H

extern int optind, opterr;
extern char *optarg;

int getopt(int argc, char *argv[], char *optstring);

#endif //XGETOPT_H