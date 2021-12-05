/*
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <dbg.h>
#include "dataElementsUtil.h"


#ifndef __USE_ISOC99
#define isblank(c) (((c) == ' ') || ((c) == '\t'))
#endif

/*====================================================================*
 *   program variables;
 *--------------------------------------------------------------------*/

static char buffer [1024] = "";
static signed c;

/*====================================================================*
 *
 *   int compare (FILE * fp, const char *sp);
 *
 *   compare file and text characters until they differ or until end
 *   of text, line or file; a match occurs when the text ends before
 *   the line or file ends;
 *
 *   spaces and tabs within the argument string or file string are
 *   ignored such that "item1", " item1 " and "item 1" all match;
 *
 *--------------------------------------------------------------------*/

static int compare (FILE * fp, const char * sp)
{
    while (isblank (*sp)) {
        sp++;
    }
    while ((*sp) && (c != '\n') && (c != EOF)) {
        if (toupper (c) != toupper (*sp)) {
            return (0);
        }
        do {
            sp++;
        }
        while (isblank (*sp));
        do {
            c = getc (fp);
        }
        while (isblank (c));
    }
    return (!*sp);
}

/*====================================================================*
 *
 *   void collect (FILE * fp);
 *
 *   collect text to end-of-line; remove leading and trailing space
 *   but preserve embedded space; replace selected escape sequences;
 *
 *   an unescaped semicolon ends the text and starts a comment that
 *   continues to the end-of-line;
 *
 *--------------------------------------------------------------------*/

static void collect (FILE * fp)

{
    char *bp = buffer;
    char *cp = buffer;
    while ((c != ';') && (c != '\n') && (c != EOF)) {
        if (c == '\\') {
            c = getc (fp);
            if (c == 'n') {
                c = '\n';
            }
            if (c == 't') {
                c = '\t';
            }
        }
        if ((cp - buffer) < (sizeof (buffer) - 1)) {
            *cp++ = c;
        }
        if (!isblank (c)) {
            bp = cp;
        }
        c = getc (fp);
    }
    *bp = (char) (0);
    return;
}

/*====================================================================*
 *
 *   void discard (FILE * fp);
 *
 *   read and discard characters until end-of-line or end-of-file
 *   is detected; read the first character of next line if end of
 *   file has not been detected;
 *
 *--------------------------------------------------------------------*/
static void discard (FILE * fp)
{
    while ((c != '\n') && (c != EOF)) {
        c = getc (fp);
    }
    if (c != EOF) {
        c = getc (fp);
    }
    return;
}

/*====================================================================*
 *
 *   Const char * configstring (const char * file, const char * part, const char * item, const char * text)
 *
 *   open the named file, locate the named part and return the named
 *   item text, if present; return alternative text if the file part
 *   or item is missing; the calling function must free returned
 *   text as it will have been dynamically allocated using strdup
 *
 *--------------------------------------------------------------------*/

const char * configstring (const char * file, const char * part, const char * item, const char * text)
{
    FILE *fp;
    if (file && part && item) {
        if ((fp = fopen ("/tmp/mad.conf", "rb"))) {
            for (c = getc (fp); c != EOF; discard (fp)) {
                while (isblank (c)) {
                    c = getc (fp);
                }
                if (c != '[') {
                    continue;
                }
                do {
                    c = getc (fp);
                }
                while (isblank (c));
                if (!compare (fp, part)) {
                    continue;
                }
                if (c != ']') {
                    continue;
                }
                for (discard (fp); (c != '[') && (c != EOF); discard (fp)) {
                    while (isblank (c)) {
                        c = getc (fp);
                    }
                    if (c == ';') {
                        continue;
                    }
                    if (!compare (fp, item)) {
                        continue;
                    }
                    if (c != '=') {
                        continue;
                    }
                    do {
                        c = getc (fp);
                    }
                    while (isblank (c));
                    collect (fp);
                    text = buffer;
                    break;
                }
                break;
            }
            fclose (fp);
        }
    }

    if (text) {
        text = strdup(text);
    }

    return text;
}

// Update default table values if the values are not read
const char *profileElementDefault(const char *Element,
        struct profileElement *DefaultTable)
{
    int Index = 0;

    if (!Element || !DefaultTable) return NULL;

    while (DefaultTable[Index].Element) {
        if (!strcmp(DefaultTable[Index].Element, Element))
            return DefaultTable[Index].Default;
        Index++;
    }

    return NULL;
}

//Read INI parameters from the configuration file
const char *profileGetOpts(const char *Section, const char *Element, struct profileElement *DefaultTable)
{
    const char *Result = NULL;
    const char *Missing = NULL;
    const char File[] = "/tmp/mad.conf" ;

    Result = configstring(File,
            Section,
            Element,
            Missing);

    if (!Result || !strlen(Result)) {
        if (Result) { free((char *) Result); }
        Result = profileElementDefault(Element, DefaultTable);

        // Allocations from the defaults table need to be strdup'ed so that
        // all return values from this function need to be free'ed. Otherwise,
        // the caller would have no way to know whether free() should be
        // called or not.
        if (Result) { Result = strdup(Result); }
    }
    return Result;

}

//Read integer INI values
int profileGetOptsInt(const char *Section, const char *Element,
        struct profileElement *DefaultTable)
{
    int Result = -1;
    const char *ResultStr = profileGetOpts(Section, Element, DefaultTable);
    if (ResultStr) {
        Result = atoi(ResultStr);
        free((char *) ResultStr);  // must cast away const-ness for free
    }

    return Result;
}

